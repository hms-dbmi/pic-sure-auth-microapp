package edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.harvard.hms.dbmi.avillach.auth.entity.Connection;
import edu.harvard.hms.dbmi.avillach.auth.entity.Role;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.Passport;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasDbgapPermission;
import edu.harvard.hms.dbmi.avillach.auth.service.AuthenticationService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.*;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class RASAuthenticationService extends OktaAuthenticationService implements AuthenticationService {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final UserService userService;
    private final boolean isEnabled;
    private final AccessRuleService accessRuleService;
    private final RoleService roleService;
    private final RASPassPortService rasPassPortService;
    private Connection rasConnection;

    /**
     * Constructor for the RASAuthenticationService
     *
     * @param userService      The user service
     * @param idp_provider_uri The IDP provider URI
     * @param connectionId     The connection ID
     * @param clientId         The client ID
     * @param clientSecret     The client secret
     */
    @Autowired
    public RASAuthenticationService(UserService userService,
                                    AccessRuleService accessRuleService,
                                    RestClientUtil restClientUtil,
                                    @Value("${ras.okta.idp.provider.is.enabled}") boolean isEnabled,
                                    @Value("${ras.okta.idp.provider.uri}") String idp_provider_uri,
                                    @Value("${ras.okta.connection.id}") String connectionId,
                                    @Value("${ras.okta.client.id}") String clientId,
                                    @Value("${ras.okta.client.secret}") String clientSecret,
                                    RoleService roleService,
                                    RASPassPortService rasPassPortService, ConnectionWebService connectionService) {
        super(idp_provider_uri, clientId, clientSecret, restClientUtil);

        this.userService = userService;
        this.isEnabled = isEnabled;
        this.roleService = roleService;
        this.rasPassPortService = rasPassPortService;

        logger.info("RASAuthenticationService is enabled: {}", isEnabled);
        logger.info("RASAuthenticationService initialized");
        logger.info("idp_provider_uri: {}", idp_provider_uri);
        logger.info("connectionId: {}", connectionId);

        this.accessRuleService = accessRuleService;
        this.rasConnection = connectionService.getConnectionByLabel("RAS");
    }

    /**
     * Authenticate the user using the code provided by the IDP. This code is exchanged for an access token.
     * The access token is then used to introspect the user. The user is then loaded from the database.
     * If the user does not exist, we will reject their login attempt.
     *
     * @param host        The host of the request
     * @param authRequest The request body
     * @return The response from the authentication attempt
     */
    @Override
    public HashMap<String, String> authenticate(Map<String, String> authRequest, String host) {
        logger.info("RAS OKTA LOGIN ATTEMPT ___ {} ___", authRequest.get("code"));

        JsonNode introspectResponse = null;
        String idToken = null;
        if (authRequest.containsKey("code") && StringUtils.isNotBlank(authRequest.get("code"))) {
            JsonNode userToken = handleCodeTokenExchange(host, authRequest.get("code"));
            introspectResponse = introspectToken(userToken);
            idToken = userToken.get("id_token").asText();
        }

        if (introspectResponse == null) {
            logger.info("LOGIN FAILED ___ USER NOT AUTHENTICATED ___ Introspection Response {}", introspectResponse);
            return null;
        }

        Optional<User> initializedUser = initializeUser(introspectResponse);
        if (initializedUser.isEmpty()) {
            logger.info("LOGIN FAILED ___ COULD NOT CREATE USER ___");
            return null;
        }

        User user = initializedUser.get();
        Optional<Passport> rasPassport = this.rasPassPortService.extractPassport(introspectResponse);

        if (rasPassport.isEmpty()) {
            logger.info("LOGIN FAILED ___ NO RAS PASSPORT FOUND ___");
            return null;
        }

        Set<RasDbgapPermission> dbgapPermissions = this.rasPassPortService.ga4gpPassportToRasDbgapPermissions(rasPassport.get().getGa4ghPassportV1());
        Optional<Set<String>> dbgapRoleNames = this.roleService.getRoleNamesForDbgapPermissions(dbgapPermissions);
        if (dbgapRoleNames.isPresent()) {
            user = userService.updateUserRoles(user, dbgapRoleNames.get());
            logger.debug("User roles updated: {}", user.getRoles().stream().map(role -> role.getName().replace("MANAGED_", "")).toArray());
        }

        String passport = introspectResponse.get("passport_jwt_v11").toString();
        user.setPassport(passport);
        userService.save(user);
        HashMap<String, String> responseMap = createUserClaims(user, idToken);
        responseMap.put("oktaIdToken", idToken);
        logger.info("LOGIN SUCCESS ___ {}:{} ___ Authorization will expire at  ___ {}___", user.getEmail(), user.getUuid().toString(), responseMap.get("expirationDate"));
        return responseMap;
    }

    private Optional<User> initializeUser(JsonNode introspectResponse) {
        Optional<User> user = userService.createRasUser(introspectResponse, this.rasConnection);
        if (user.isEmpty()) {
            logger.info("FAILED TO LOAD OR CREATE USER");
            return Optional.empty();
        }

        User currentUser = user.get();
        currentUser.setGeneralMetadata(generateRasUserMetadata(currentUser).toString());
        logger.info("USER METADATA SUCCESSFULLY ADDED - USER DATA: {}", currentUser.getGeneralMetadata());

        clearCache(currentUser);
        return Optional.of(currentUser);
    }

    /**
     * Create user claims to return to the client
     *
     * @param user The user
     * @return The user claims as a HashMap
     */
    private HashMap<String, String> createUserClaims(User user, String idToken) {
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("name", user.getName());
        claims.put("email", user.getEmail());
        claims.put("sub", user.getSubject());
        // We need the id_token to be returned, so we can use it at logout
        return userService.getUserProfileResponse(claims);
    }

    private void clearCache(User user) {
        userService.evictFromCache(user.getSubject());
        accessRuleService.evictFromCache(user.getSubject());
    }

    /**
     * Generate the user metadata that will be stored in the database. This metadata is used to determine the user's
     * role and other information.
     *
     * @param user               The user
     * @return The user metadata as an ObjectNode
     */
    protected ObjectNode generateRasUserMetadata(User user) {
        // JsonNode is immutable, so we need to convert it to an ObjectNode
        ObjectNode objectNode = new ObjectMapper().createObjectNode();

        objectNode.put("role", "user");
        objectNode.put("sub", user.getSubject());
        objectNode.put("user_id", user.getUuid().toString());
        objectNode.put("username", user.getEmail());
        objectNode.put("email", user.getEmail());
        objectNode.put("idp", this.rasConnection.getLabel());

        return objectNode;
    }


    @Override
    public String getProvider() {
        return "ras";
    }

    @Override
    public boolean isEnabled() {
        return this.isEnabled;
    }

    public void setRasConnection(Connection rasConnection) {
        this.rasConnection = rasConnection;
    }

}