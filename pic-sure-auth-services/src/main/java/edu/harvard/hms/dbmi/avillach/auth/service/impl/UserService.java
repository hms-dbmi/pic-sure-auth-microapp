package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.dbmi.avillach.data.repository.BaseRepository;
import edu.harvard.dbmi.avillach.util.exception.ProtocolException;
import edu.harvard.dbmi.avillach.util.response.PICSUREResponseOKwithMsgAndContent;
import edu.harvard.hms.dbmi.avillach.auth.entity.Connection;
import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.entity.Role;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.repository.ConnectionRepository;
import edu.harvard.hms.dbmi.avillach.auth.repository.RoleRepository;
import edu.harvard.hms.dbmi.avillach.auth.repository.UserRepository;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
import java.util.stream.Collectors;

@Service
public class UserService extends BaseEntityService<User> {

    private final Logger logger = LoggerFactory.getLogger(UserService.class.getName());

    private final TOSService tosService;
    private final UserRepository userRepository;
    private final ConnectionRepository connectionRepository;

    private final RoleRepository roleRepository;
    private final String clientSecret;

    private final long tokenExpirationTime;
    private static final long defaultTokenExpirationTime = 1000L * 60 * 60; // 1 hour TODO: Move to a global configuration or enum?

    @Autowired
    public UserService(TOSService tosService, UserRepository userRepository, ConnectionRepository connectionRepository, RoleRepository roleRepository,
                       @Value("${application.client.secret}") String clientSecret, @Value("${application.token.expiration.time}") long tokenExpirationTime) {
        super(User.class);
        this.tosService = tosService;
        this.userRepository = userRepository;
        this.connectionRepository = connectionRepository;
        this.roleRepository = roleRepository;
        this.clientSecret = clientSecret;
        this.tokenExpirationTime = tokenExpirationTime > 0 ? tokenExpirationTime : defaultTokenExpirationTime;
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
     * @param inputUser
     * @param originalUser there could be no original user when adding a new user
     * @return
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
        boolean allowAdd = true;
        for (User user : users) {
            logger.debug("Adding User " + user);
            if (!allowUpdateSuperAdminRole(currentUser, user, null)) { // TODO: The allowUpdateSuperAdminRole is a private method
                allowAdd = false;
                break;
            }

            if (user.getEmail() == null) {
                try {
                    HashMap<String, String> metadata = new HashMap<String, String>(new ObjectMapper().readValue(user.getGeneralMetadata(), Map.class));
                    List<String> emailKeys = metadata.keySet().stream().filter((key) -> {
                        return key.toLowerCase().contains("email");
                    }).collect(Collectors.toList());
                    if (emailKeys.size() > 0) {
                        user.setEmail(metadata.get(emailKeys.get(0)));
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        if (allowAdd) {
            ResponseEntity<?> updateResponse = addEntity(users);
            sendUserUpdateEmailsFromResponse(updateResponse);
            return updateResponse;
        } else {
            logger.error("updateUser() user - " + currentUser.getUuid() + " - with roles [" + currentUser.getRoleString() + "] - is not allowed to grant "
                    + AuthNaming.AuthRoleNaming.SUPER_ADMIN + " role when adding a user.");
            throw new ProtocolException(Response.Status.BAD_REQUEST, "Not allowed to add a user with a " + AuthNaming.AuthRoleNaming.SUPER_ADMIN + " privilege associated.");
        }
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
            throw new ProtocolException(Response.Status.BAD_REQUEST, "Not allowed to update a user with changes associated to " + AuthNaming.AuthRoleNaming.SUPER_ADMIN + " privilege.");
        }
    }

    private void sendUserUpdateEmailsFromResponse(ResponseEntity<?> updateResponse) {
        logger.debug("Sending email");
        try {
            Object entity = updateResponse.getEntity(); // TODO: Determine how to replicate this given the new approach
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
}
