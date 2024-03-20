package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.dbmi.avillach.util.exception.ApplicationException;
import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.exceptions.NotAuthorizedException;
import edu.harvard.hms.dbmi.avillach.auth.repository.UserRepository;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.AuthorizationService;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;

import java.security.Principal;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.stream.Collectors;

import static edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil.parseToken;

/**
 * <p>Token introspection endpoint called by an application to validate a user's token and permissions by request.</p>
 *
 * <p>Here, a registered application asks if the user behind a token is allowed to perform certain activities by
 * showing this endpoint the token and where the user wants to go.</p>
 * <p>To accomplish this, this endpoint validates the incoming token, then checks if the user behind the token
 * is authorized to access the URLs they queried and send data along with them. The AuthorizationService class handles authorization
 * {@link AuthorizationService} at the access rule level, but this endpoint handles token validation and pre-check at the privilege level.</p>
 */
@Api
@Controller("/token")
public class TokenController {

    private Logger logger = LoggerFactory.getLogger(TokenController.class);

    private final UserRepository userRepo;

    private final AuthorizationService authorizationService;

    @Context
    SecurityContext securityContext;

    @Autowired
    public TokenController(UserRepository userRepo, AuthorizationService authorizationService) {
        this.userRepo = userRepo;
        this.authorizationService = authorizationService;
    }

    @ApiOperation(value = "Token introspection endpoint for user to retrieve a valid token")
    @PostMapping("/inspect")
    @Consumes("application/json")
    public ResponseEntity<?> inspectToken(
            @ApiParam(required = true, value = "A JSON object that at least" +
                    " include a user the token for validation")
            Map<String, Object> inputMap) {
        logger.info("TokenInspect starting...");
        TokenInspection tokenInspection = _inspectToken(inputMap);
        if (tokenInspection.message != null)
            tokenInspection.responseMap.put("message", tokenInspection.message);

        logger.info("Finished token introspection.");
        return PICSUREResponse.success(tokenInspection.responseMap);
    }

    /**
     * This endpoint currently is only for a user token to be refreshed.
     * Application token won't work here.
     *
     * @return
     */
    @ApiOperation(value = "To refresh current user's token if the user is an active user")
    @GET
    @Path("/refresh")
    public ResponseEntity<?> refreshToken(@RequestHeader("Authorization") String authorizationHeader) {
        logger.debug("RefreshToken starting...");

        // still need to check if the user is in the database or not,
        // just in case something changes in the middle
        Principal principal = securityContext.getUserPrincipal();
        if (!(principal instanceof User)) {
            logger.error("refreshToken() Security context didn't have a user stored.");
        }
        User user = (User) principal;

        if (user.getUuid() == null) {
            logger.error("refreshToken() Stored user doesn't have a uuid.");
            return PICSUREResponse.applicationError("Inner application error, please contact admin.");
        }

        user = userRepo.getById(user.getUuid());
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
        if (!subject.equals(claims.getSubject())) {
            logger.error("refreshToken() user subject is not the same as the subject of the input token");
            return PICSUREResponse.applicationError("Inner application error, try again or contact admin.");
        }

        Date expirationDate = new Date(Calendar.getInstance().getTimeInMillis() + JAXRSConfiguration.tokenExpirationTime);
        String refreshedToken = JWTUtil.createJwtToken(JAXRSConfiguration.clientSecret,
                claims.getId(),
                claims.getIssuer(),
                claims,
                subject,
                JAXRSConfiguration.tokenExpirationTime);

        logger.debug("Finished RefreshToken and new token has been generated.");
        return PICSUREResponse.success(Map.of(
                "token", refreshedToken,
                "expirationDate", ZonedDateTime.ofInstant(expirationDate.toInstant(), ZoneOffset.UTC).toString()
        ));
    }


    /**
     * @param inputMap
     * @return
     */
    private TokenInspection _inspectToken(Map<String, Object> inputMap) {
        logger.debug("_inspectToken, the incoming token map is: {}", inputMap.entrySet()
                .stream()
                .map(entry -> entry.getKey() + " - " + entry.getValue())
                .collect(Collectors.joining(", ")));

        TokenInspection tokenInspection = new TokenInspection();

        String token = (String) inputMap.get("token");
        if (token == null || token.isEmpty()) {
            logger.error("Token - " + token + " is blank");
            tokenInspection.message = "Token not found";
            return tokenInspection;
        }

        // parse the token based on client secret
        // don't need to check if jws is null or not, since parse function has already checked
        Jws<Claims> jws;
        try {
            jws = parseToken(token);

            /*
             * token has been verified, now we remove it from inputMap, so further logs will not be able to log
             * the token accidentally!
             */
            inputMap.remove("token");
        } catch (NotAuthorizedException ex) {
            // only when the token is for sure invalid, we can dump it into the log.
            logger.error("_inspectToken() the token - " + token + " - is invalid with exception: " + ex.getMessage());
            tokenInspection.message = ex.getMessage();
            return tokenInspection;
        }


        Application application;

        try {
            application = (Application) securityContext.getUserPrincipal();
        } catch (ClassCastException ex) {
            logger.error(securityContext.getUserPrincipal().getName()
                    + " - " + securityContext.getUserPrincipal().getClass().getSimpleName() +
                    " - is trying to use token introspection endpoint" +
                    ", but it is not an application");
            throw new ApplicationException("The application token does not associate with an application but "
                    + securityContext.getUserPrincipal().getClass().getSimpleName());
        }

        // application null check should be finished when application token goes through the JWTFilter authentication process,
        // here we just double check it to prevent a null application object goes further.
        if (application == null) {
            logger.error("_inspectToken() There is no application in securityContext, which shall not be.");
            throw new ApplicationException("Inner application error, please ask admin to check the log.");
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

        user = userRepo.getUniqueResultByColumn("subject", subject);
        logger.info("_inspectToken() user with subject - " + subject + " - exists in database");
        if (user == null) {
            logger.error("_inspectToken() could not find user with subject " + subject);
            tokenInspection.message = "user doesn't exist";
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
            tokenInspection.responseMap.put("active", true);
            ArrayList<String> roles = new ArrayList<String>();
            for (Privilege p : user.getTotalPrivilege()) {
                roles.add(p.getName());
            }
            tokenInspection.responseMap.put("roles", String.join(",", roles));
        } else {
            if (errorMsg != null)
                tokenInspection.message = errorMsg;
            return tokenInspection;
        }

        tokenInspection.responseMap.putAll(jws.getBody());

        // attach all privileges associated with the application to the responseMap
        tokenInspection.responseMap.put("privileges", user.getPrivilegeNameSetByApplication(application));


        logger.info("_inspectToken() Successfully inspect and return response map: "
                + tokenInspection.responseMap.entrySet()
                .stream()
                .map(entry -> entry.getKey() + " - " + entry.getValue())
                .collect(Collectors.joining(", ")));
        return tokenInspection;
    }

    /**
     * inner used token introspection class with active:false included
     */
    private class TokenInspection {
        Map<String, Object> responseMap = new HashMap<>();
        String message = null;

        public TokenInspection() {
            responseMap.put("active", false);
        }
    }

}
