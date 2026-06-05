package edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.harvard.hms.dbmi.avillach.auth.entity.Connection;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.entity.UserClaims;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.Ga4ghPassportV1;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.Passport;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasDbgapPermission;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasIal2UserInfo;
import edu.harvard.hms.dbmi.avillach.auth.service.AuthenticationService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.*;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
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
    private final RoleService roleService;
    private final RASPassPortService rasPassPortService;
    private final CacheEvictionService cacheEvictionService;
    private Connection rasConnection;
    private final String rasPassportIssuer;
    private final RasUserinfoService rasUserinfoService;
    private final ObjectMapper objectMapper = new ObjectMapper();

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
                                    RestClientUtil restClientUtil,
                                    @Value("${ras.okta.idp.provider.is.enabled}") boolean isEnabled,
                                    @Value("${ras.okta.idp.provider.uri}") String idp_provider_uri,
                                    @Value("${ras.okta.connection.id}") String connectionId,
                                    @Value("${ras.okta.client.id}") String clientId,
                                    @Value("${ras.okta.client.secret}") String clientSecret,
                                    @Value("${ras.passport.issuer}") String rasPassportIssuer,
                                    RoleService roleService,
                                    RASPassPortService rasPassPortService,
                                    ConnectionWebService connectionService, CacheEvictionService cacheEvictionService,
                                    RasUserinfoService rasUserinfoService) {
        super(idp_provider_uri, clientId, clientSecret, restClientUtil);

        this.userService = userService;
        this.isEnabled = isEnabled;
        this.roleService = roleService;
        this.rasPassPortService = rasPassPortService;
        this.rasPassportIssuer = rasPassportIssuer;

        logger.info("RASAuthenticationService is enabled: {}", isEnabled);
        logger.info("RASAuthenticationService initialized");
        logger.info("idp_provider_uri: {}", idp_provider_uri);
        logger.info("connectionId: {}", connectionId);

        this.rasConnection = connectionService.getConnectionByLabel("RAS");
        this.cacheEvictionService = cacheEvictionService;
        this.rasUserinfoService = rasUserinfoService;
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
    public HashMap<String, String> authenticate(Map<String, String> authRequest, String host) throws JsonProcessingException {
        logger.info("RAS OKTA LOGIN ATTEMPT ___ CODE {}", authRequest.get("code"));

        JsonNode introspectResponse = null;
        String idToken = null;
        if (authRequest.containsKey("code") && StringUtils.isNotBlank(authRequest.get("code"))) {
            JsonNode userToken = handleCodeTokenExchange(host, authRequest.get("code"));
            introspectResponse = introspectToken(userToken);
            idToken = userToken.get("id_token").asText();
            logger.debug("RAS OKTA LOGIN ATTEMPT ___ INTROSPECTION RESPONSE RECEIVED: {}", introspectResponse != null);
        }

        if (introspectResponse == null) {
            logger.info("LOGIN FAILED ___ USER NOT AUTHENTICATED ___ INTROSPECTION RESPONSE {} ___ CODE {}", introspectResponse, authRequest.get("code"));
            return null;
        }

        String oktaUserId = extractOktaUserId(introspectResponse);
        RasIal2UserInfo rasUserinfo = rasUserinfoService.fetchUserinfo(oktaUserId);
        logger.info("RAS userinfo enrichment {} for okta user {}", rasUserinfo != null ? "applied" : "skipped", oktaUserId);

        Optional<User> initializedUser = initializeUser(rasUserinfo);
        if (initializedUser.isEmpty()) {
            logger.info("LOGIN FAILED ___ COULD NOT CREATE USER ___ USER ID {} ___ CODE {}", introspectResponse.path("userid").asText(""), authRequest.get("code"));
            return null;
        }

        User user = initializedUser.get();
        Optional<Passport> rasPassport = extractAndVerifyPassport(authRequest, introspectResponse, user);
        if (rasPassport.isEmpty()) {
            return null;
        }

        user = updateRasUserRoles(authRequest.get("code"), user, rasPassport.get());
        setUserPassport(authRequest, introspectResponse, user);
        UserClaims userClaims = buildUserClaims(user, rasPassport.get(), rasUserinfo);
        HashMap<String, String> responseMap = userService.getUserProfileResponse(userClaims);

        if (responseMap != null) {
            responseMap.put("oktaIdToken", idToken);
            logger.info("LOGIN SUCCESS ___ USER {}:{} ___ WITH ROLES ___ {} ___ AUTHORIZATION WILL EXPIRE AT  ___ {} ___ CODE {}",
                    user.getSubject(), user.getUuid().toString(),
                    user.getRoles().stream().map(role -> role.getName().replace("MANAGED_", "")).collect(Collectors.joining(",")),
                    responseMap.get("expirationDate"), authRequest.get("code"));
        }

        return responseMap;
    }

    /**
     * Extract the OKTA user id (the "uid" claim) used to look up the stored RAS token in the Okta
     * Management API. This is NOT the RAS "sub" used as the user lookup key. Returns null if absent,
     * in which case userinfo enrichment is skipped (login still succeeds).
     */
    private String extractOktaUserId(JsonNode introspectResponse) {
        JsonNode uid = introspectResponse.get("uid");
        if (uid == null || uid.isNull() || uid.asText().isBlank()) {
            logger.warn("Introspection response missing 'uid'; RAS userinfo enrichment will be skipped");
            return null;
        }
        return uid.asText();
    }

    private Optional<Passport> extractAndVerifyPassport(Map<String, String> authRequest, JsonNode introspectResponse, User user) {
        Optional<Passport> rasPassport = this.rasPassPortService.extractPassport(introspectResponse);
        if (rasPassport.isEmpty()) {
            logger.info("LOGIN FAILED ___ NO RAS PASSPORT FOUND ___ USER: {} ___ CODE {}", user.getSubject(), authRequest.get("code"));
            return Optional.empty();
        }

        if (rasPassPortService.isExpired(rasPassport.get())) {
            logger.error("validateRASPassport() LOGIN FAILED ___ PASSPORT IS EXPIRED ___ USER: {} ___ CODE {}", user.getSubject(), authRequest.get("code"));
            return Optional.empty();
        }

        if (!rasPassport.get().getIss().equals(this.rasPassportIssuer)) {
            logger.error("validateRASPassport() LOGIN FAILED ___ PASSPORT ISSUER IS NOT CORRECT ___ USER: {} ___ " +
                         "EXPECTED ISSUER {} ___ ACTUAL ISSUER {} ___ CODE {}",
                    user.getSubject(), this.rasPassportIssuer, rasPassport.get().getIss(), authRequest.get("code"));
            return Optional.empty();
        }
        return rasPassport;
    }

    protected User updateRasUserRoles(String code, User user, Passport rasPassport) {
        logger.info("RAS PASSPORT FOUND ___ USER: {} ___ PASSPORT: {} ___ CODE {}", user.getSubject(), rasPassport, code);
        Set<Optional<Ga4ghPassportV1>> ga4ghPassports = rasPassport.getGa4ghPassportV1().stream().map(JWTUtil::parseGa4ghPassportV1).filter(Optional::isPresent).collect(Collectors.toSet());
        Set<RasDbgapPermission> dbgapPermissions = this.rasPassPortService.ga4ghPassportToRasDbgapPermissions(ga4ghPassports);
        Set<String> dbgapRoleNames = this.roleService.getRoleNamesForDbgapPermissions(dbgapPermissions);
        user = userService.updateUserRoles(user, dbgapRoleNames);

        Set<String> userConsentStrings = dbgapPermissions.stream()
                .map(permission -> permission.getPhsId() + "." + permission.getConsentGroup()).collect(Collectors.toSet());
        user = userService.updateUserConsents(user, userConsentStrings);
        logger.debug("USER {} ROLES UPDATED {} ___ CODE {}",
                user.getSubject(),
                user.getRoles().stream().map(role -> role.getName().replace("MANAGED_", "")).toArray(),
                code);
        return user;
    }

    private Optional<User> initializeUser(RasIal2UserInfo rasUserinfo) {
        Optional<User> user = userService.createRasUser(rasUserinfo, this.rasConnection);
        if (user.isEmpty()) {
            logger.info("FAILED TO LOAD OR CREATE USER");
            return Optional.empty();
        }

        User currentUser = user.get();
        currentUser.setGeneralMetadata(generateRasUserMetadata(currentUser, rasUserinfo).toString());
        logger.info("RAS user loaded/created: {}", currentUser.getSubject());
        logger.info("USER METADATA SUCCESSFULLY ADDED FOR USER: {}", currentUser.getSubject());

        cacheEvictionService.evictCache(currentUser);
        return Optional.of(currentUser);
    }

    /**
     * Create user claims to return to the client
     *
     * @param user               The user
     * @param rasPassport        The RAS passport
     * @param rasUserinfo        The RAS userinfo response
     * @return The user claims as a HashMap
     */
    private UserClaims buildUserClaims(User user, Passport rasPassport, RasIal2UserInfo rasUserinfo) throws JsonProcessingException {
        UserClaims userClaims = new UserClaims();
        userClaims.setUuid(user.getUuid().toString());
        userClaims.setSub(user.getSubject());
        userClaims.setEmail(user.getEmail());
        userClaims.setIdp(this.rasConnection.getLabel());
        userClaims.setName(user.getName());
        userClaims.setUserid(rasUserinfo.getUserId());
        userClaims.setPreferred_username(rasUserinfo.getPreferredUsername());
        userClaims.setUser_permission_group(extractPermissionGroupFromPassport(rasPassport));
        userClaims.setRoles(userService.addRoleClaims(user));

        RasIal2UserInfo.FederatedIdentities federated = rasUserinfo.getFederatedIdentities();
        if (federated != null) {
            userClaims.setFederated_sources(this.objectMapper.writeValueAsString(federated.getSources()));
            Map<String, RasIal2UserInfo.FederatedIdentityDetail> identities = federated.getIdentities();
            if (identities != null && !identities.isEmpty()) {
                RasIal2UserInfo.FederatedIdentityDetail era = identities.get("era");
                userClaims.setEra_commons_id(era != null ? era.getUserId() : "");
            }
        }

        return userClaims;
    }

    private String extractPermissionGroupFromPassport(Passport rasPassport) {
        try {
            List<String> ga4ghPassports = rasPassport.getGa4ghPassportV1();
            if (ga4ghPassports == null || ga4ghPassports.isEmpty()) {
                return null;
            }
            Optional<Ga4ghPassportV1> parsedPassport = JWTUtil.parseGa4ghPassportV1(ga4ghPassports.get(0));
            if (parsedPassport.isPresent() && parsedPassport.get().getGa4ghVisaV1() != null) {
                return parsedPassport.get().getGa4ghVisaV1().getSource();
            }
        } catch (Exception e) {
            logger.error("Failed to extract permission group from passport: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Generate the user metadata that will be stored in the database. This metadata is used to determine the user's
     * role and other information.
     *
     * @param user The user
     * @return The user metadata as an ObjectNode
     */
    protected ObjectNode generateRasUserMetadata(User user, RasIal2UserInfo rasUserinfo) {
        // JsonNode is immutable, so we need to convert it to an ObjectNode
        ObjectNode objectNode = new ObjectMapper().createObjectNode();

        objectNode.put("role", "user");
        objectNode.put("sub", user.getSubject());
        objectNode.put("user_id", user.getUuid().toString());
        objectNode.put("username", user.getEmail());
        objectNode.put("email", user.getEmail());
        objectNode.put("idp", this.rasConnection.getLabel());

        if (rasUserinfo != null) {
            RasIal2UserInfo.FederatedIdentities federatedIdentitiesIal2 = rasUserinfo.getFederatedIdentitiesIal2();
            if (federatedIdentitiesIal2 != null && federatedIdentitiesIal2.getDefaultIdentity() != null) {
                if (StringUtils.isNotBlank(federatedIdentitiesIal2.getDefaultIdentity())) {
                    objectNode.put("default_identity", federatedIdentitiesIal2.getDefaultIdentity());
                }

                if (StringUtils.isNotBlank(federatedIdentitiesIal2.getAuthenticatedIdentity())) {
                    objectNode.put("authenticated_identity", federatedIdentitiesIal2.getAuthenticatedIdentity());
                }
            }
        }

        return objectNode;
    }

    private void setUserPassport(Map<String, String> authRequest, JsonNode introspectResponse, User user) {
        String passport = introspectResponse.get("passport_jwt_v11").toString();
        user.setPassport(passport);
        userService.save(user);
        logger.info("RAS PASSPORT SUCCESSFULLY ADDED TO USER: {} ___ CODE {}", user.getSubject(), authRequest.get("code"));
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