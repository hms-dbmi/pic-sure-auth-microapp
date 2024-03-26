package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.dbmi.avillach.util.exception.ProtocolException;
import edu.harvard.dbmi.avillach.util.response.PICSUREResponseOKwithMsgAndContent;
import edu.harvard.hms.dbmi.avillach.auth.entity.*;
import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.repository.ApplicationRepository;
import edu.harvard.hms.dbmi.avillach.auth.repository.ConnectionRepository;
import edu.harvard.hms.dbmi.avillach.auth.repository.RoleRepository;
import edu.harvard.hms.dbmi.avillach.auth.repository.UserRepository;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
import edu.harvard.hms.dbmi.avillach.auth.utils.JsonUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import javax.transaction.Transactional;
import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.*;

@Service
public class UserService extends BaseEntityService<User> {

    private final Logger logger = LoggerFactory.getLogger(UserService.class.getName());

    private final MailService mailService;
    private final TOSService tosService;
    private final UserRepository userRepository;
    private final ConnectionRepository connectionRepository;
    private final ApplicationRepository applicationRepository;
    private final RoleRepository roleRepository;
    private final String clientSecret;
    private final long tokenExpirationTime;
    private static final long defaultTokenExpirationTime = 1000L * 60 * 60; // 1 hour

    public long longTermTokenExpirationTime;

    private final String applicationUUID;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public UserService(MailService mailService, TOSService tosService, UserRepository userRepository, ConnectionRepository connectionRepository, RoleRepository roleRepository, ApplicationRepository applicationRepository,
                       @Value("${application.client.secret}") String clientSecret, @Value("${application.token.expiration.time}") long tokenExpirationTime,
                       @Value("${application.default.}") String applicationUUID, @Value("${application.long.term.token.expiration.time}") long longTermTokenExpirationTime) {
        super(User.class);
        this.mailService = mailService;
        this.tosService = tosService;
        this.userRepository = userRepository;
        this.connectionRepository = connectionRepository;
        this.roleRepository = roleRepository;
        this.clientSecret = clientSecret;
        this.tokenExpirationTime = tokenExpirationTime > 0 ? tokenExpirationTime : defaultTokenExpirationTime;
        this.applicationRepository = applicationRepository;
        this.applicationUUID = applicationUUID;

        long defaultLongTermTokenExpirationTime = 1000L * 60 * 60 * 24 * 30; //
        this.longTermTokenExpirationTime = longTermTokenExpirationTime > 0 ? longTermTokenExpirationTime : defaultLongTermTokenExpirationTime;

    }

    public HashMap<String, String> getUserProfileResponse(Map<String, Object> claims) {
        logger.info("getUserProfileResponse() starting...");

        HashMap<String, String> responseMap = new HashMap<String, String>();
        logger.info("getUserProfileResponse() initialized map");

        logger.info("getUserProfileResponse() using claims:" + claims.toString());

        String token = JWTUtil.createJwtToken(
                this.clientSecret,
                "whatever",
                "edu.harvard.hms.dbmi.psama",
                claims,
                claims.get("sub").toString(),
                this.tokenExpirationTime
        );
        logger.info("getUserProfileResponse() PSAMA JWT token has been generated. Token:" + token);
        responseMap.put("token", token);

        logger.info("getUserProfileResponse() .usedId field is set");
        responseMap.put("userId", claims.get("sub").toString());

        logger.info("getUserProfileResponse() .email field is set");
        responseMap.put("email", claims.get("email").toString());

        logger.info("getUserProfileResponse() acceptedTOS is set");

        boolean acceptedTOS = tosService.hasUserAcceptedLatest(claims.get("sub").toString());

        responseMap.put("acceptedTOS", "" + acceptedTOS);

        logger.info("getUserProfileResponse() expirationDate is set");
        Date expirationDate = new Date(Calendar.getInstance().getTimeInMillis() + this.tokenExpirationTime);
        responseMap.put("expirationDate", ZonedDateTime.ofInstant(expirationDate.toInstant(), ZoneOffset.UTC).toString());

        logger.info("getUserProfileResponse() finished");
        return responseMap;
    }

    public ResponseEntity<?> getEntityById(String userId) {
        return getEntityById(userId, this.userRepository);
    }

    public ResponseEntity<?> getEntityAll() {
        return getEntityAll(this.userRepository);
    }

    public ResponseEntity<?> addEntity(List<User> users) {
        return addEntity(users, this.userRepository);

    }

    /**
     * This check is to prevent non-super-admin user to create/remove a super admin role
     * against a user(include themselves). Only super admin user could perform such actions.
     *
     * <p>
     * if operations not related to super admin role updates, this will return true.
     * </p>
     * <p>
     * The logic here is checking the state of the super admin role in the input and output users,
     * if the state is changed, check if the user is a super admin to determine if the user could perform the action.
     *
     * @param currentUser  the user trying to perform the action
     * @param inputUser   the user that is going to be updated
     * @param originalUser there could be no original user when adding a new user
     * @return true if the user could perform the action, false otherwise
     */
    private boolean allowUpdateSuperAdminRole(
            @NotNull User currentUser,
            @NotNull User inputUser,
            User originalUser) {

        // if current user is a super admin, this check will return true
        for (Role role : currentUser.getRoles()) {
            for (Privilege privilege : role.getPrivileges()) {
                if (privilege.getName().equals(AuthNaming.AuthRoleNaming.SUPER_ADMIN)) {
                    return true;
                }
            }
        }

        boolean inputUserHasSuperAdmin = false;
        boolean originalUserHasSuperAdmin = false;

        for (Role role : inputUser.getRoles()) {
            for (Privilege privilege : role.getPrivileges()) {
                if (privilege.getName().equals(AuthNaming.AuthRoleNaming.SUPER_ADMIN)) {
                    inputUserHasSuperAdmin = true;
                    break;
                }
            }
        }

        if (originalUser != null) {
            for (Role role : originalUser.getRoles()) {
                for (Privilege privilege : role.getPrivileges()) {
                    if (privilege.getName().equals(AuthNaming.AuthRoleNaming.SUPER_ADMIN)) {
                        originalUserHasSuperAdmin = true;
                        break;
                    }
                }
            }

            // when they equals, nothing has changed, a non super admin user could perform the action
            return inputUserHasSuperAdmin == originalUserHasSuperAdmin;
        } else {
            // if inputUser has super admin, it should return false
            return !inputUserHasSuperAdmin;
        }

    }

    public ResponseEntity<?> addUsers(List<User> users) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        User currentUser = (User) securityContext.getAuthentication().getPrincipal();
        if (currentUser == null || currentUser.getUuid() == null) {
            logger.error("Security context didn't have a user stored.");
            return PICSUREResponse.applicationError("Inner application error, please contact admin.");
        }

        checkAssociation(users);
        for (User user : users) {
            logger.debug("Adding User " + user);
            if (!allowUpdateSuperAdminRole(currentUser, user, null)) { // TODO: The allowUpdateSuperAdminRole is a private method
                logger.error("updateUser() user - " + currentUser.getUuid() + " - with roles [" + currentUser.getRoleString() + "] - is not allowed to grant "
                        + AuthNaming.AuthRoleNaming.SUPER_ADMIN + " role when adding a user.");
                throw new IllegalArgumentException("Not allowed to add a user with a " + AuthNaming.AuthRoleNaming.SUPER_ADMIN + " privilege associated.");
            }

            if (user.getEmail() == null) {
                try {
                    HashMap<String, String> metadata = new HashMap<String, String>(new ObjectMapper().readValue(user.getGeneralMetadata(), Map.class));
                    List<String> emailKeys = metadata.keySet().stream().filter((key) -> key.toLowerCase().contains("email")).toList();
                    if (!emailKeys.isEmpty()) {
                        user.setEmail(metadata.get(emailKeys.getFirst()));
                    }
                } catch (IOException e) {
                    logger.error("Failed to parse metadata for email address", e);
                }
            }
        }

        ResponseEntity<?> updateResponse = addEntity(users);
        sendUserUpdateEmailsFromResponse(updateResponse);
        return updateResponse;
    }

    /**
     * check all referenced field if they are already in database. If
     * they are in database, then retrieve it by id, and attach it to
     * user object.
     *
     * @param users A list of users
     */
    private void checkAssociation(List<User> users) {
        for (User user : users) {
            if (user.getRoles() != null) {
                Set<Role> roles = new HashSet<>();
                user.getRoles().forEach(t -> this.roleRepository.addObjectToSet(roles, this.roleRepository, t)); // TODO: We need to fix the exception that is thrown here
                user.setRoles(roles);
            }

            if (user.getConnection() != null) {
                Connection connection = this.connectionRepository.getUniqueResultByColumn("id", user.getConnection().getId());
                user.setConnection(connection);
            }
        }
    }

    @Transactional // TODO: Can this be moved further down the call hierarchy to improve performance?
    public ResponseEntity<?> updateUser(List<User> users) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        User currentUser = (User) securityContext.getAuthentication().getPrincipal();
        if (currentUser == null || currentUser.getUuid() == null) {
            logger.error("Security context didn't have a user stored.");
            return PICSUREResponse.applicationError("Inner application error, please contact admin.");
        }

        checkAssociation(users);
        boolean allowUpdate = true;
        for (User user : users) {

            User originalUser = this.userRepository.getById(user.getUuid());
            if (!allowUpdateSuperAdminRole(currentUser, user, originalUser)) {
                allowUpdate = false;
                break;
            }
        }

        if (allowUpdate) {
            ResponseEntity<?> updateResponse = updateEntity(users, this.userRepository);
            sendUserUpdateEmailsFromResponse(updateResponse);
            return updateResponse;
        } else {
            logger.error("updateUser() user - " + currentUser.getUuid() + " - with roles [" + currentUser.getRoleString() + "] - is not allowed to grant or remove "
                    + AuthNaming.AuthRoleNaming.SUPER_ADMIN + " privilege.");
            throw new IllegalArgumentException("Not allowed to update a user with changes associated to " + AuthNaming.AuthRoleNaming.SUPER_ADMIN + " privilege.");
        }
    }

    private void sendUserUpdateEmailsFromResponse(ResponseEntity<?> updateResponse) {
        logger.debug("Sending email");
        try {
            Object entity = updateResponse.getBody(); // TODO: Determine how to replicate this given the new approach
            if (entity != null && entity instanceof PICSUREResponseOKwithMsgAndContent) {
                PICSUREResponseOKwithMsgAndContent okResponse = (PICSUREResponseOKwithMsgAndContent) entity;
                List<User> addedUsers = (List<User>) okResponse.getContent();
                String message = okResponse.getMessage();
                for (User user : addedUsers) {
                    try {
                        mailService.sendUsersAccessEmail(user);
                    } catch (MessagingException e) {
                        logger.error("Failed to send email! " + e.getLocalizedMessage());
                        logger.debug("Exception Trace: ", e);
                        okResponse.setMessage(message + "  WARN - could not send email to user " + user.getEmail() + " see logs for more info");
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Failed to send email - unhandled exception: ", e);
        }
        logger.debug("finished email sending method");
    }

    public ResponseEntity<?> getCurrentUser(String authorizationHeader, Boolean hasToken) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        User user = (User) securityContext.getAuthentication().getPrincipal();
        if (user == null || user.getUuid() == null) {
            logger.error("Security context didn't have a user stored.");
            return PICSUREResponse.applicationError("Inner application error, please contact admin.");
        }

        user = this.userRepository.getById(user.getUuid());
        if (user == null) {
            logger.error("When retrieving current user, it returned null");
            return PICSUREResponse.applicationError("Inner application error, please contact admin.");
        }

        User.UserForDisplay userForDisplay = new User.UserForDisplay()
                .setEmail(user.getEmail())
                .setPrivileges(user.getPrivilegeNameSet())
                .setUuid(user.getUuid().toString())
                .setAcceptedTOS(this.tosService.hasUserAcceptedLatest(user.getSubject()));

        // currently, the queryScopes are simple combination of queryScope string together as a set.
        // We are expecting the queryScope string as plain string. If it is a JSON, we could change the
        // code to use JsonUtils.mergeTemplateMap(Map, Map)
        Set<Privilege> privileges = user.getTotalPrivilege();
        if (privileges != null && !privileges.isEmpty()) {
            Set<String> scopes = new TreeSet<>();
            privileges.stream().filter(privilege -> privilege.getQueryScope() != null).forEach(privilege -> {
                try {
                    Arrays.stream(objectMapper.readValue(privilege.getQueryScope(), String[].class))
                            .filter(x -> x != null)
                            .forEach(scopeList -> scopes.addAll(Arrays.asList(scopeList)));
                } catch (IOException e) {
                    logger.error("Parsing issue for privilege " + privilege.getUuid() + " queryScope", e);
                }
            });
            userForDisplay.setQueryScopes(scopes);
        }

        if (hasToken != null) {

            if (user.getToken() != null && !user.getToken().isEmpty()) {
                userForDisplay.setToken(user.getToken());
            } else {
                user.setToken(generateUserLongTermToken(authorizationHeader));
                this.userRepository.merge(user);
                userForDisplay.setToken(user.getToken());
            }
        }

        return PICSUREResponse.success(userForDisplay);
    }

    public ResponseEntity<?> getQueryTemplate(String applicationId) {
        if (applicationId == null || applicationId.trim().isEmpty()) {
            logger.error("getQueryTemplate() input application UUID is null or empty.");
            throw new IllegalArgumentException("Input application UUID is incorrect.");
        }

        SecurityContext securityContext = SecurityContextHolder.getContext();
        User user = (User) securityContext.getAuthentication().getPrincipal();
        if (user == null || user.getUuid() == null) {
            logger.error("Security context didn't have a user stored.");
            return PICSUREResponse.applicationError("Inner application error, please contact admin.");
        }

        user = this.userRepository.getById(user.getUuid());
        if (user == null) {
            logger.error("When retrieving current user, it returned null");
            return PICSUREResponse.applicationError("Inner application error, please contact admin.");
        }

        Application application = this.applicationRepository.getById(UUID.fromString(applicationId));

        if (application == null) {
            logger.error("getQueryTemplate() cannot find corresponding application by UUID: " + applicationId);
            throw new IllegalArgumentException("Cannot find application by input UUID: " + applicationId);
        }

        return PICSUREResponse.success(
                Map.of("queryTemplate", mergeTemplate(user, application)));
    }

    public ResponseEntity<?> getDefaultQueryTemplate() {
        return getQueryTemplate(this.applicationUUID);
    }

    private String mergeTemplate(User user, Application application) {
        String resultJSON;
        Map mergedTemplateMap = null;
        for (Privilege privilege : user.getPrivilegesByApplication(application)) {
            String template = privilege.getQueryTemplate();
            logger.debug("mergeTemplate() processing template:" + template);
            if (template == null || template.trim().isEmpty()) {
                continue;
            }
            Map<String, Object> templateMap = null;
            try {
                templateMap = objectMapper.readValue(template, Map.class);
            } catch (IOException ex) {
                logger.error("mergeTemplate() cannot convert stored queryTemplate using Jackson, the queryTemplate is: " + template);
                throw new IllegalArgumentException("Inner application error, please contact admin.");
            }

            if (templateMap == null) {
                continue;
            }

            if (mergedTemplateMap == null) {
                mergedTemplateMap = templateMap;
                continue;
            }

            mergedTemplateMap = JsonUtils.mergeTemplateMap(mergedTemplateMap, templateMap);
        }

        try {
            resultJSON = objectMapper.writeValueAsString(mergedTemplateMap);
        } catch (JsonProcessingException ex) {
            logger.error("mergeTemplate() cannot convert map to json string. The map mergedTemplate is: " + mergedTemplateMap);
            throw new IllegalArgumentException("Inner application error, please contact admin.");
        }

        return resultJSON;

    }

    @Transactional
    public ResponseEntity<?> refreshUserToken(HttpHeaders httpHeaders) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        User user = (User) securityContext.getAuthentication().getPrincipal();
        if (user == null || user.getUuid() == null) {
            logger.error("Security context didn't have a user stored.");
            return PICSUREResponse.applicationError("Inner application error, please contact admin.");
        }

        user = this.userRepository.getById(user.getUuid());
        if (user == null) {
            logger.error("When retrieving current user, it returned null");
            return PICSUREResponse.applicationError("Inner application error, please contact admin.");
        }

        String authorizationHeader = httpHeaders.getFirst("Authorization");
        String longTermToken = generateUserLongTermToken(authorizationHeader);
        user.setToken(longTermToken);

        this.userRepository.merge(user);

        return PICSUREResponse.success(Map.of("userLongTermToken", longTermToken));
    }

    /**
     * Logic here is, retrieve the subject of the user from httpHeader. Then generate a long term one
     * with LONG_TERM_TOKEN_PREFIX| in front of the subject to be able to distinguish with regular ones, since
     * long term token only generated for accessing certain things to, in some degrees, decrease the insecurity.
     *
     * @param authorizationHeader the authorization header
     * @return the long term token
     * @throws IllegalArgumentException if the authorization header is not presented
     */
    private String generateUserLongTermToken(String authorizationHeader) {
        if (!StringUtils.isNotBlank(authorizationHeader)) {
            throw new IllegalArgumentException("Authorization header is not presented.");
        }

        Optional<String> token = JWTUtil.getTokenFromAuthorizationHeader(authorizationHeader);
        if (token.isEmpty()) {
            throw new IllegalArgumentException("Token is not presented in the authorization header.");
        }

        Jws<Claims> jws = JWTUtil.parseToken(token.get());

        Claims claims = jws.getBody();
        String tokenSubject = claims.getSubject();

        if (tokenSubject.startsWith(AuthNaming.LONG_TERM_TOKEN_PREFIX + "|")) {
            // considering the subject already contains a "|"
            // to prevent infinitely adding the long term token prefix
            // we will grab the real subject here
            tokenSubject = tokenSubject.substring(AuthNaming.LONG_TERM_TOKEN_PREFIX.length() + 1);
        }

        return JWTUtil.createJwtToken(clientSecret,
                claims.getId(),
                claims.getIssuer(),
                claims,
                AuthNaming.LONG_TERM_TOKEN_PREFIX + "|" + tokenSubject,
                this.longTermTokenExpirationTime);
    }
}