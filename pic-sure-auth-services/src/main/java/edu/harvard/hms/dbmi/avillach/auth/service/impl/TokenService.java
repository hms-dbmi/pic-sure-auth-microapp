package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.exceptions.NotAuthorizedException;
import edu.harvard.hms.dbmi.avillach.auth.model.TokenInspection;
import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.repository.UserRepository;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

import static edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil.parseToken;

@Service
public class TokenService {

    private final static Logger logger = LoggerFactory.getLogger(TokenService.class);

    private final AuthorizationService authorizationService;

    private final UserRepository userRepository;

    private final long tokenExpirationTime;
    private final String clientSecret;

    private static final long defaultTokenExpirationTime = 1000L * 60 * 60; // 1 hour TODO: Move to a global configuration or enum?

    @Autowired
    public TokenService(AuthorizationService authorizationService, UserRepository userRepository,
                        @Value("${application.client.secret}") String clientSecret,
                        @Value("${application.token.expiration.time}") long tokenExpirationTime) {
        this.authorizationService = authorizationService;
        this.userRepository = userRepository;
        this.clientSecret = clientSecret;
        this.tokenExpirationTime = tokenExpirationTime > 0 ? tokenExpirationTime : defaultTokenExpirationTime;
    }

    public ResponseEntity<?> inspectToken(Map<String, Object> inputMap) {
        logger.info("TokenInspect starting...");
        TokenInspection tokenInspection;
        try {
            tokenInspection = _inspectToken(inputMap);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
        if (tokenInspection.getMessage() != null) {
            tokenInspection.addField("message", tokenInspection.getMessage());
        }

        logger.info("Finished token introspection.");
        return PICSUREResponse.success(tokenInspection.getResponseMap());
    }

    private TokenInspection _inspectToken(Map<String, Object> inputMap) throws IllegalAccessException {
        logger.debug("_inspectToken, the incoming token map is: {}", inputMap.entrySet()
                .stream()
                .map(entry -> entry.getKey() + " - " + entry.getValue())
                .collect(Collectors.joining(", ")));

        TokenInspection tokenInspection = new TokenInspection();
        String token = (String) inputMap.get("token");
        if (token == null || token.isEmpty()) {
            logger.error("Token - " + token + " is blank");
            tokenInspection.setMessage("Token not found");
            return tokenInspection;
        }

        // parse the token based on client secret
        // don't need to check if jws is null or not, since parse function has already checked
        Jws<Claims> jws;
        try {
            jws = JWTUtil.parseToken(token);

            /*
             * token has been verified, now we remove it from inputMap, so further logs will not be able to log
             * the token accidentally!
             */
            inputMap.remove("token");
        } catch (NotAuthorizedException ex) {
            // only when the token is for sure invalid, we can dump it into the log.
            logger.error("_inspectToken() the token - " + token + " - is invalid with exception: " + ex.getMessage());
            tokenInspection.setMessage(ex.getMessage());
            return tokenInspection;
        }


        Application application;
        try {
            application = (Application) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        } catch (ClassCastException ex) {
            SecurityContext securityContext = SecurityContextHolder.getContext();
            String principalName = securityContext.getAuthentication().getName();
            logger.error(principalName
                    + " - " + principalName +
                    " - is trying to use token introspection endpoint" +
                    ", but it is not an application");
            throw new IllegalAccessException("The application token does not associate with an application but "
                    + principalName);
        }

        // application null check should be finished when application token goes through the JWTFilter authentication process,
        // here we just double check it to prevent a null application object goes further.
        if (application == null) {
            logger.error("_inspectToken() There is no application in securityContext, which shall not be.");
            throw new NullPointerException("Inner application error, please ask admin to check the log.");
        }

        String subject = jws.getBody().getSubject();

        // get the user based on subject field in token
        User user;

        // check if the token is the special LONG_TERM_TOKEN,
        // the differences between this special token and normal token is
        // one user only has one long_term_token stored in database,
        // this token needs to be exactly the same as the database one.
        // If the token refreshed, the old one will be invalid. But normal
        // token will not invalid the old ones if refreshed.
        boolean isLongTermToken = false;
        if (subject.startsWith(AuthNaming.LONG_TERM_TOKEN_PREFIX)) {
            subject = subject.substring(AuthNaming.LONG_TERM_TOKEN_PREFIX.length() + 1);
            isLongTermToken = true;
        }

        user = this.userRepository.getUniqueResultByColumn("subject", subject);
        logger.info("_inspectToken() user with subject - " + subject + " - exists in database");
        if (user == null) {
            logger.error("_inspectToken() could not find user with subject " + subject);
            tokenInspection.setMessage("user doesn't exist");
            return tokenInspection;
        }


        //Essentially we want to return jws.getBody() with an additional active: true field
        //only under certain circumstances, the token will return active
        boolean isAuthorizationPassed = false;
        String errorMsg = null;

        // long term token needs to be the same as the token in the database user table, if
        // not the token might has been compromised, which will not go through the authorization check
        boolean isLongTermTokenCompromised = false;
        if (isLongTermToken && !token.equals(user.getToken())) {
            // in long_term_token mode, the token needs to be exactly the same as the token in user table
            isLongTermTokenCompromised = true;
            logger.error("_inspectToken User " + user.getUuid() + "|" + user.getSubject()
                    + "is sending a long term token that is not matching the record in database user table.");
            errorMsg = "Cannot find matched long term token, your token might have been refreshed.";
        }

        // we go through the authorization layer check only if we need to in order to improve the performance
        // the logic here, if the token associated with a user, we will start the authorization check.
        // If the current application has at least one privilege, the user must have one privilege associated to the application
        // pass the accessRule check if there is any accessRules associated with.
        if (application.getPrivileges() == null || application.getPrivileges().isEmpty()) {
            // if no privileges associated
            isAuthorizationPassed = true;
            //we still want to log this, though.
            logger.info("ACCESS_LOG ___ " + user.getUuid() + "," + user.getEmail() + "," + user.getName() +
                    " ___ has been granted access to execute query ___ " + inputMap.get("request") + " ___ in application ___ " + application.getName()
                    + " ___ NO APP PRIVILEGES DEFINED");
        } else if (!isLongTermTokenCompromised
                && user.getRoles() != null
                // The protocol between applications and PSAMA is application will
                // attach everything that needs to be verified in request field of inputMap
                // besides token. So here we should attach everything in request.
                && authorizationService.isAuthorized(application, inputMap.get("request"), user)) {
            isAuthorizationPassed = true;
        } else {
            // if isLongTermTokenCompromised flag is true,
            // the error message has already been set previously
            if (!isLongTermTokenCompromised)
                errorMsg = "User doesn't have enough privileges.";
        }

        if (isAuthorizationPassed) {
            tokenInspection.addField("active", true);
            ArrayList<String> roles = new ArrayList<String>();
            for (Privilege p : user.getTotalPrivilege()) {
                roles.add(p.getName());
            }
            tokenInspection.addField("roles", String.join(",", roles));
        } else {
            tokenInspection.setMessage(errorMsg);
            return tokenInspection;
        }

        tokenInspection.addAllFields(jws.getBody());

        // attach all privileges associated with the application to the responseMap
        tokenInspection.addField("privileges", user.getPrivilegeNameSetByApplication(application));


        logger.info("_inspectToken() Successfully inspect and return response map: "
                + tokenInspection.getResponseMap().entrySet()
                .stream()
                .map(entry -> entry.getKey() + " - " + entry.getValue())
                .collect(Collectors.joining(", ")));
        return tokenInspection;
    }

    public ResponseEntity<?> refreshToken(String authorizationHeader) {
        logger.debug("RefreshToken starting...");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        if (!(principal instanceof User)) {
            logger.error("refreshToken() Security context didn't have a user stored.");
        }

        if (!(principal instanceof User user)) {
            logger.error("refreshToken() Principal is not an instance of User.");
            throw new NotAuthorizedException("User not found");
        }

        if (user.getUuid() == null) {
            logger.error("refreshToken() Stored user doesn't have a uuid.");
            return PICSUREResponse.applicationError("Inner application error, please contact admin.");
        }

        user = this.userRepository.getById(user.getUuid());
        if (user == null) {
            logger.error("refreshToken() When retrieving current user, it returned null, the user might be removed from database");
            throw new NotAuthorizedException("User doesn't exist anymore");
        }

        if (!user.isActive()) {
            logger.error("refreshToken() The user has just been deactivated.");
            throw new NotAuthorizedException("User has been deactivated.");
        }

        String subject = user.getSubject();
        if (subject == null || subject.isEmpty()) {
            logger.error("refreshToken() subject doesn't exist in the user.");
        }

        // parse origin token
        Jws<Claims> jws;
        try {
            String token = JWTUtil.getTokenFromAuthorizationHeader(authorizationHeader).orElseThrow(() -> new NotAuthorizedException("Token not found"));
            jws = parseToken(token);

        } catch (NotAuthorizedException ex) {
            return PICSUREResponse.protocolError("Cannot parse original token");
        }

        Claims claims = jws.getBody();

        // just check if the subject is along with the database record,
        // just in case something has changed in middle
        if (StringUtils.isNotBlank(subject) && !subject.equals(claims.getSubject())) {
            logger.error("refreshToken() user subject is not the same as the subject of the input token");
            return PICSUREResponse.applicationError("Inner application error, try again or contact admin.");
        }

        Date expirationDate = new Date(Calendar.getInstance().getTimeInMillis() + this.tokenExpirationTime);
        String refreshedToken = JWTUtil.createJwtToken(this.clientSecret,
                claims.getId(),
                claims.getIssuer(),
                claims,
                subject,
                this.tokenExpirationTime);

        logger.debug("Finished RefreshToken and new token has been generated.");
        return PICSUREResponse.success(Map.of(
                "token", refreshedToken,
                "expirationDate", ZonedDateTime.ofInstant(expirationDate.toInstant(), ZoneOffset.UTC).toString()
        ));
    }


}