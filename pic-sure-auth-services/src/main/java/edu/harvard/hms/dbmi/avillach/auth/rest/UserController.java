package edu.harvard.hms.dbmi.avillach.auth.rest;

import com.fasterxml.jackson.core.JsonProcessingException;
import edu.harvard.dbmi.avillach.util.exception.ApplicationException;
import edu.harvard.dbmi.avillach.util.exception.ProtocolException;
import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.entity.*;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.TOSService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.UserService;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
import edu.harvard.hms.dbmi.avillach.auth.utils.JsonUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import jakarta.annotation.security.RolesAllowed;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.transaction.Transactional;
import java.io.IOException;
import java.util.*;

import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.ADMIN;
import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.SUPER_ADMIN;

/**
 * <p>Endpoint for service handling business logic for users.</p>
 */
@Api
@Controller("/user")
public class UserController {

    private final static Logger logger = LoggerFactory.getLogger(UserController.class);

    private final UserService userService;

    private final TOSService tosService;

    @Autowired
    public UserController(UserService userService, TOSService tosService) {
        this.userService = userService;
        this.tosService = tosService;
    }

    @ApiOperation(value = "GET information of one user with the UUID, requires ADMIN or SUPER_ADMIN roles")
    @RolesAllowed({ADMIN, SUPER_ADMIN})
    @GetMapping(path = "/{userId}", produces = "application/json")
    public ResponseEntity<?> getUserById(
            @ApiParam(required = true, value = "The UUID of the user to fetch information about")
            @PathVariable("userId") String userId) {
        return this.userService.getEntityById(userId);
    }

    @ApiOperation(value = "GET a list of existing users, requires ADMIN or SUPER_ADMIN roles")
    @RolesAllowed({ADMIN, SUPER_ADMIN})
    @GetMapping(produces = "application/json")
    public ResponseEntity<?> getUserAll() {
        return this.userService.getEntityAll();
    }

    @ApiOperation(value = "POST a list of users, requires ADMIN role")
    @Transactional // TODO: Move this to the service layer
    @RolesAllowed({ADMIN})
    @PostMapping(produces = "application/json")
    public ResponseEntity<?> addUser(
            @ApiParam(required = true, value = "A list of user in JSON format")
            List<User> users) {
        return this.userService.addUsers(users);

    }

    @ApiOperation(value = "Update a list of users, will only update the fields listed, requires ADMIN role")
    @RolesAllowed({ADMIN})
    @PutMapping(produces = "application/json")
    public ResponseEntity<?> updateUser(List<User> users) {
        return this.userService.updateUser(users);
    }

    /**
     * For the long term token, current logic is,
     * every time a user hit this endpoint <code>/me</code> with the query parameter ?hasToken presented,
     * it will refresh the long term token.
     *
     * @param hasToken
     * @return
     */
    @ApiOperation(value = "Retrieve information of current user")
    @Transactional // TODO: Move this to the service layer
    @GetMapping(produces = "application/json", path = "/me")
    public ResponseEntity<?> getCurrentUser(
            @RequestHeader("Authorization") String authorizationHeader,
            @ApiParam(required = false, value = "Attribute that represents if a long term token will attach to the response")
            @RequestParam("hasToken") Boolean hasToken) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        User user = (User) securityContext.getAuthentication().getPrincipal();
        if (user == null || user.getUuid() == null) {
            logger.error("Security context didn't have a user stored.");
            return PICSUREResponse.applicationError("Inner application error, please contact admin.");
        }

        user = userRepo.getById(user.getUuid());
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
                userRepo.merge(user);
                userForDisplay.setToken(user.getToken());
            }
        }

        return PICSUREResponse.success(userForDisplay);
    }

    @ApiOperation(value = "Retrieve the queryTemplate of certain application by given application Id for the currentUser ")
    @Transactional
    @GET
    @Path("/me/queryTemplate/{applicationId}")
    public ResponseEntity<?> getQueryTemplate(
            @ApiParam(value = "Application Id for the returning queryTemplate")
            @PathParam("applicationId") String applicationId) {

        if (applicationId == null || applicationId.trim().isEmpty()) {
            logger.error("getQueryTemplate() input application UUID is null or empty.");
            throw new ProtocolException("Input application UUID is incorrect.");
        }

        User user = (User) securityContext.getUserPrincipal();
        if (user == null || user.getUuid() == null) {
            logger.error("Security context didn't have a user stored.");
            return PICSUREResponse.applicationError("Inner application error, please contact admin.");
        }

        user = userRepo.getById(user.getUuid());
        if (user == null) {
            logger.error("When retrieving current user, it returned null");
            return PICSUREResponse.applicationError("Inner application error, please contact admin.");
        }

        Application application = applicationRepo.getById(UUID.fromString(applicationId));

        if (application == null) {
            logger.error("getQueryTemplate() cannot find corresponding application by UUID: " + applicationId);
            throw new ProtocolException("Cannot find application by input UUID: " + applicationId);
        }

        return PICSUREResponse.success(
                Map.of("queryTemplate", mergeTemplate(user, application)));

    }

    @ApiOperation(value = "Retrieve the queryTemplate of default application")
    @Transactional
    @GET
    @Path("/me/queryTemplate")
    public ResponseEntity<?> getQueryTemplate() {
        return getQueryTemplate(JAXRSConfiguration.defaultApplicationUUID);
    }


    private String mergeTemplate(User user, Application application) {
        String resultJSON = null;
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
                throw new ApplicationException("Inner application error, please contact admin.");
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
            throw new ApplicationException("Inner application error, please contact admin.");
        }

        return resultJSON;

    }

    /**
     * For the long term token, current logic is,
     * every time a user hit this endpoint /me
     * with the query parameter ?hasToken presented,
     * it will refresh the long term token.
     *
     * @param httpHeaders
     * @param hasToken
     * @return
     */
    @ApiOperation(value = "refresh the long term tokne of current user")
    @Transactional
    @GET
    @Path("/me/refresh_long_term_token")
    public ResponseEntity<?> refreshUserToken(
            @RequestHeader HttpHeaders httpHeaders,
            @ApiParam(required = false, value = "A flag represents if the long term token will be returned or not")
            @QueryParam("hasToken") Boolean hasToken) {
        User user = (User) securityContext.getUserPrincipal();
        if (user == null || user.getUuid() == null) {
            logger.error("Security context didn't have a user stored.");
            return PICSUREResponse.applicationError("Inner application error, please contact admin.");
        }

        user = userRepo.getById(user.getUuid());
        if (user == null) {
            logger.error("When retrieving current user, it returned null");
            return PICSUREResponse.applicationError("Inner application error, please contact admin.");
        }

        String longTermToken = generateUserLongTermToken(httpHeaders);
        user.setToken(longTermToken);

        userRepo.merge(user);

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
                longTermTokenExpirationTime);
    }





}
