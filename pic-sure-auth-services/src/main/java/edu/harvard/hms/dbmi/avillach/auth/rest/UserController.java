package edu.harvard.hms.dbmi.avillach.auth.rest;

import com.fasterxml.jackson.core.JsonProcessingException;
import edu.harvard.dbmi.avillach.util.exception.ApplicationException;
import edu.harvard.dbmi.avillach.util.exception.ProtocolException;
import edu.harvard.hms.dbmi.avillach.auth.entity.*;
import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
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
        return this.userService.getCurrentUser(authorizationHeader, hasToken);
    }

    @ApiOperation(value = "Retrieve the queryTemplate of certain application by given application Id for the currentUser ")
    @Transactional // TODO: Move this to the service layer
    @GetMapping(path = "/me/queryTemplate/{applicationId}", produces = "application/json")
    public ResponseEntity<?> getQueryTemplate(
            @ApiParam(value = "Application Id for the returning queryTemplate")
            @PathVariable("applicationId") String applicationId) {
        return this.userService.getQueryTemplate(applicationId);
    }

    @ApiOperation(value = "Retrieve the queryTemplate of default application")
    @GetMapping(path = "/me/queryTemplate", produces = "application/json")
    public ResponseEntity<?> getQueryTemplate() {
        return this.userService.getDefaultQueryTemplate();
    }

    /**
     * For the long term token, current logic is,
     * every time a user hit this endpoint /me
     * with the query parameter ?hasToken presented,
     * it will refresh the long term token.
     *
     * @param httpHeaders the http headers
     * @return the refreshed long term token
     */
    @ApiOperation(value = "refresh the long term tokne of current user")
    @GetMapping(path = "/me/refresh_long_term_token", produces = "application/json")
    public ResponseEntity<?> refreshUserToken(
            @RequestHeader HttpHeaders httpHeaders) {
        return this.userService.refreshUserToken(httpHeaders);
    }







}
