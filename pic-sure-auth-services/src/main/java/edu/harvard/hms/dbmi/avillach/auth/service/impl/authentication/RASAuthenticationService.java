package edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.harvard.hms.dbmi.avillach.auth.entity.Connection;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.entity.UserClaims;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.Ga4ghPassportV1;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.Passport;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasDbgapPermission;
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
    private final RasPassportSignatureVerifier rasPassportSignatureVerifier;
    private final CacheEvictionService cacheEvictionService;
    private Connection rasConnection;
    private final String rasPassportIssuer;
    private final boolean enforceIal2;

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
                                    @Value("${ras.enforce.ial2:false}") boolean enforceIal2,
                                    RoleService roleService,
                                    RASPassPortService rasPassPortService,
                                    RasPassportSignatureVerifier rasPassportSignatureVerifier,
                                    ConnectionWebService connectionService, CacheEvictionService cacheEvictionService) {
        super(idp_provider_uri, clientId, clientSecret, restClientUtil);

        this.userService = userService;
        this.isEnabled = isEnabled;
        this.roleService = roleService;
        this.rasPassPortService = rasPassPortService;
        this.rasPassportSignatureVerifier = rasPassportSignatureVerifier;
        this.rasPassportIssuer = rasPassportIssuer;
        this.enforceIal2 = enforceIal2;

        logger.info("RASAuthenticationService is enabled: {}", isEnabled);
        logger.info("RASAuthenticationService initialized");
        logger.info("idp_provider_uri: {}", idp_provider_uri);
        logger.info("connectionId: {}", connectionId);

        this.rasConnection = connectionService.getConnectionByLabel("RAS");
        this.cacheEvictionService = cacheEvictionService;
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
        logger.info("RAS OKTA LOGIN ATTEMPT ___ CODE {}", authRequest.get("code"));

        JsonNode introspectResponse = null;
        String idToken = null;
        if (authRequest.containsKey("code") && StringUtils.isNotBlank(authRequest.get("code"))) {
            JsonNode userToken = handleCodeTokenExchange(host, authRequest.get("code"));
            introspectResponse = introspectToken(userToken);
            idToken = userToken.get("id_token").asText();
            logger.debug("RAS OKTA LOGIN ATTEMPT ___ INTROSPECTION RESPONSE {}", introspectResponse);
        }

        if (introspectResponse == null) {
            logger.info("LOGIN FAILED ___ USER NOT AUTHENTICATED ___ INTROSPECTION RESPONSE {} ___ CODE {}", introspectResponse, authRequest.get("code"));
            return null;
        }

        // Enforce IAL2/AAL2 for RAS logins when configured. Opt-in via ras.enforce.ial2 because
        // IAL1-only IdPs (eRA Commons, Google) cannot meet IAL2 and would otherwise be locked out.
        if (this.enforceIal2 && !validateAssuranceLevels(introspectResponse)) {
            logger.info("LOGIN FAILED ___ ASSURANCE LEVEL BELOW REQUIRED IAL2/AAL2 ___ CODE {}", authRequest.get("code"));
            return null;
        }

        Optional<User> initializedUser = initializeUser(introspectResponse);
        if (initializedUser.isEmpty()) {
            logger.info("LOGIN FAILED ___ COULD NOT CREATE USER ___ INTROSPECTION RESPONSE {} ___ CODE {}", introspectResponse, authRequest.get("code"));
            return null;
        }

        User user = initializedUser.get();
        Optional<Passport> rasPassport = extractAndVerifyPassport(authRequest, introspectResponse, user);
        if (rasPassport.isEmpty()) return null;
        user = updateRasUserRoles(authRequest.get("code"), user, rasPassport.get());
        setUserPassport(authRequest, introspectResponse, user);
        UserClaims userClaims = buildUserClaims(user, introspectResponse, rasPassport.get());
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

    private Optional<Passport> extractAndVerifyPassport(Map<String, String> authRequest, JsonNode introspectResponse, User user) {
        JsonNode passportNode = introspectResponse.get("passport_jwt_v11");
        if (passportNode == null) {
            logger.info("LOGIN FAILED ___ NO RAS PASSPORT FOUND ___ USER: {} ___ CODE {}", user.getSubject(), authRequest.get("code"));
            return Optional.empty();
        }

        // Cryptographically verify RAS's signature on the passport JWT BEFORE trusting any claim it
        // carries. Okta brokers this connection, so this signature is the only guarantee the dbGaP
        // permissions were issued by RAS and not tampered with in transit. Fail closed.
        if (!this.rasPassportSignatureVerifier.isSignatureValid(passportNode.asText())) {
            logger.error("validateRASPassport() LOGIN FAILED ___ PASSPORT SIGNATURE INVALID ___ USER: {} ___ CODE {}",
                    user.getSubject(), authRequest.get("code"));
            return Optional.empty();
        }

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

        // Defense in depth: each embedded GA4GH visa is independently RAS-signed. Verify every visa,
        // not just the outer passport, so a tampered visa cannot grant dbGaP permissions.
        List<String> visas = rasPassport.get().getGa4ghPassportV1();
        if (visas != null) {
            for (String visa : visas) {
                if (!this.rasPassportSignatureVerifier.isSignatureValid(visa)) {
                    logger.error("validateRASPassport() LOGIN FAILED ___ VISA SIGNATURE INVALID ___ USER: {} ___ CODE {}",
                            user.getSubject(), authRequest.get("code"));
                    return Optional.empty();
                }
            }
        }
        return rasPassport;
    }

    /**
     * Verify the authentication (AAL) and identity (IAL) assurance levels carried in the {@code acr}
     * claim meet the minimum required to access controlled-access (CADR) data. Per the NIH RAS rule
     * this is AAL >= 2 AND (IAL >= 2 OR InCommon IAP = high). Only consulted for RAS logins when
     * {@code ras.enforce.ial2} is enabled.
     */
    protected boolean validateAssuranceLevels(JsonNode introspectResponse) {
        JsonNode acrNode = introspectResponse.get("acr");
        if (acrNode == null || StringUtils.isBlank(acrNode.asText())) {
            logger.error("validateAssuranceLevels() no acr claim present in introspection response");
            return false;
        }

        String acr = acrNode.asText();
        int aal = parseAssuranceLevel(acr, "aal");
        int ial = parseAssuranceLevel(acr, "ial");
        return aal >= 2 && (ial >= 2 || hasInCommonIapHigh(acr));
    }

    /**
     * InCommon federation IdPs express identity proofing via an Identity Assurance Profile rather than
     * a numeric IAL; IAP "high" is CADR-eligible.
     */
    private boolean hasInCommonIapHigh(String acr) {
        for (String token : acr.split("\\s+")) {
            if (token.endsWith("/assurance/iap/high")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Parse the numeric level out of an {@code acr} value for a given assurance type. The {@code acr}
     * claim is a space-delimited list of URIs such as
     * {@code https://stsstg.nih.gov/assurance/aal/2 https://stsstg.nih.gov/assurance/ial/2}.
     *
     * @return the highest level found for the type, or 0 if none is present.
     */
    private int parseAssuranceLevel(String acr, String type) {
        String marker = "/assurance/" + type + "/";
        int highest = 0;
        for (String token : acr.split("\\s+")) {
            int idx = token.indexOf(marker);
            if (idx < 0) {
                continue;
            }
            try {
                int level = Integer.parseInt(token.substring(idx + marker.length()).trim());
                highest = Math.max(highest, level);
            } catch (NumberFormatException e) {
                logger.error("parseAssuranceLevel() could not parse {} level from acr token {}", type, token);
            }
        }
        return highest;
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

    private Optional<User> initializeUser(JsonNode introspectResponse) {
        Optional<User> user = userService.createRasUser(introspectResponse, this.rasConnection);
        if (user.isEmpty()) {
            logger.info("FAILED TO LOAD OR CREATE USER");
            return Optional.empty();
        }

        User currentUser = user.get();
        currentUser.setGeneralMetadata(generateRasUserMetadata(currentUser).toString());
        logger.info("USER METADATA SUCCESSFULLY ADDED - USER DATA: {}", currentUser.getGeneralMetadata());

        cacheEvictionService.evictCache(currentUser);
        return Optional.of(currentUser);
    }

    /**
     * Create user claims to return to the client
     *
     * @param user               The user
     * @param introspectResponse The OKTA introspect response
     * @param rasPassport        The RAS passport
     * @return The user claims as a HashMap
     */
    private UserClaims buildUserClaims(User user, JsonNode introspectResponse, Passport rasPassport) {
        UserClaims userClaims = new UserClaims();
        userClaims.setUuid(user.getUuid().toString());
        userClaims.setSub(user.getSubject());
        userClaims.setEmail(user.getEmail());
        userClaims.setIdp(this.rasConnection.getLabel());
        userClaims.setName(user.getName());
        userClaims.setUserid(introspectResponse.get("userid").asText());
        userClaims.setPreferred_username(introspectResponse.get("preferred_username").asText());
        userClaims.setUser_permission_group(extractPermissionGroupFromPassport(rasPassport));
        userClaims.setRoles(userService.addRoleClaims(user));

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