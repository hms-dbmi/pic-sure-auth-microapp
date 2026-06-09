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
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasOidcTokens;
import edu.harvard.hms.dbmi.avillach.auth.service.AuthenticationService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.*;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
import io.jsonwebtoken.Claims;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Authenticates PIC-SURE users directly against NIH RAS via OIDC. The claim-acquisition layer
 * (authorize → code → token exchange → ID-token validation → userinfo) is handled by
 * {@link RasOidcClient}; the resulting merged claims object preserves the shape of the old
 * Okta introspection response so the downstream pipeline is unchanged.
 */
@Service
public class RASAuthenticationService implements AuthenticationService {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final UserService userService;
    private final boolean isEnabled;
    private final boolean enforceIal2;
    private final RoleService roleService;
    private final RASPassPortService rasPassPortService;
    private final CacheEvictionService cacheEvictionService;
    private final RasOidcClient rasOidcClient;
    private final OidcFlowStateStore stateStore;
    private Connection rasConnection;
    private final String rasPassportIssuer;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public RASAuthenticationService(UserService userService,
                                    RoleService roleService,
                                    RASPassPortService rasPassPortService,
                                    ConnectionWebService connectionService,
                                    CacheEvictionService cacheEvictionService,
                                    RasOidcClient rasOidcClient,
                                    OidcFlowStateStore stateStore,
                                    @Value("${ras.idp.provider.is.enabled}") boolean isEnabled,
                                    @Value("${ras.enforce.ial2}") boolean enforceIal2,
                                    @Value("${ras.passport.issuer}") String rasPassportIssuer) {
        this.userService = userService;
        this.isEnabled = isEnabled;
        this.enforceIal2 = enforceIal2;
        this.roleService = roleService;
        this.rasPassPortService = rasPassPortService;
        this.rasOidcClient = rasOidcClient;
        this.stateStore = stateStore;
        this.rasPassportIssuer = rasPassportIssuer;

        logger.info("RASAuthenticationService is enabled: {}", isEnabled);
        logger.info("RASAuthenticationService enforcing IAL2/AAL2: {}", enforceIal2);

        this.rasConnection = connectionService.getConnectionByLabel("RAS");
        this.cacheEvictionService = cacheEvictionService;
    }

    /**
     * Authenticate the user with the authorization code returned by RAS. The code is exchanged
     * directly with RAS for tokens; the ID token is signature-validated and bound to this flow's
     * nonce; assurance levels are enforced from the ID token's acr; the v1.1 userinfo response
     * supplies all rich claims. Downstream user provisioning is unchanged from the Okta-brokered
     * flow. Returns null on any failure.
     */
    @Override
    public HashMap<String, String> authenticate(Map<String, String> authRequest, String host) {
        String code = authRequest.get("code");
        String state = authRequest.get("state");
        if (StringUtils.isBlank(code) || StringUtils.isBlank(state)) {
            logger.info("RAS LOGIN FAILED ___ MISSING CODE OR STATE");
            return null;
        }

        Optional<OidcFlowStateStore.FlowState> flow = stateStore.consume(state);
        if (flow.isEmpty()) {
            logger.info("RAS LOGIN FAILED ___ UNKNOWN, EXPIRED, OR REUSED STATE");
            return null;
        }

        RasOidcTokens tokens = rasOidcClient.exchangeCode(code, host, flow.get().codeVerifier());
        if (tokens == null) {
            logger.info("RAS LOGIN FAILED ___ CODE-FOR-TOKEN EXCHANGE FAILED");
            return null;
        }

        Optional<Claims> idTokenClaims = rasOidcClient.validateIdToken(tokens.idToken(), flow.get().nonce());
        if (idTokenClaims.isEmpty()) {
            logger.info("RAS LOGIN FAILED ___ ID TOKEN VALIDATION FAILED");
            return null;
        }

        // RAS audits all activity against this transaction id; log it on every subsequent line.
        String txn = idTokenClaims.get().get("txn", String.class);

        if (!validateAssuranceLevels(idTokenClaims.get().get("acr", String.class))) {
            logger.info("RAS LOGIN FAILED ___ ASSURANCE BELOW AAL2/IAL2 ___ TXN {}", txn);
            return null;
        }

        JsonNode userinfo = rasOidcClient.fetchUserinfo(tokens.accessToken());
        if (userinfo == null) {
            logger.info("RAS LOGIN FAILED ___ USERINFO CALL FAILED ___ TXN {}", txn);
            return null;
        }

        RasIal2UserInfo rasUserinfo = parseUserinfo(userinfo);
        if (rasUserinfo == null) {
            logger.info("RAS LOGIN FAILED ___ COULD NOT PARSE USERINFO ___ TXN {}", txn);
            return null;
        }

        // Single claims object shaped like the old introspection response (userinfo ∪ ID-token claims).
        JsonNode mergedClaims = rasOidcClient.mergeClaims(userinfo, idTokenClaims.get());

        Optional<User> initializedUser = initializeUser(rasUserinfo);
        if (initializedUser.isEmpty()) {
            logger.info("RAS LOGIN FAILED ___ COULD NOT CREATE USER ___ TXN {}", txn);
            return null;
        }

        User user = initializedUser.get();
        Optional<Passport> rasPassport = extractAndVerifyPassport(mergedClaims, user);
        if (rasPassport.isEmpty()) {
            return null;
        }

        user = updateRasUserRoles(txn, user, rasPassport.get());
        setUserPassport(txn, mergedClaims, user);
        UserClaims userClaims = buildUserClaims(user, rasPassport.get(), rasUserinfo);
        if (userClaims == null) {
            logger.info("RAS LOGIN FAILED ___ COULD NOT BUILD USER CLAIMS ___ USER: {} ___ TXN {}", user.getSubject(), txn);
            return null;
        }
        HashMap<String, String> responseMap = userService.getUserProfileResponse(userClaims);

        if (responseMap != null) {
            responseMap.put("idToken", tokens.idToken());
            logger.info("LOGIN SUCCESS ___ USER {}:{} ___ WITH ROLES ___ {} ___ AUTHORIZATION WILL EXPIRE AT ___ {} ___ TXN {}",
                    user.getSubject(), user.getUuid().toString(),
                    user.getRoles().stream().map(role -> role.getName().replace("MANAGED_", "")).collect(Collectors.joining(",")),
                    responseMap.get("expirationDate"), txn);
        }

        return responseMap;
    }

    /**
     * Enforces IAL2/AAL2 from the validated ID token's space-delimited acr URIs
     * (e.g. {@code https://stsstg.nih.gov/assurance/aal/2 https://stsstg.nih.gov/assurance/ial/2}).
     * When {@code ras.enforce.ial2=false} every acr (including absent) is accepted.
     */
    boolean validateAssuranceLevels(String acr) {
        if (!enforceIal2) {
            return true;
        }
        if (StringUtils.isBlank(acr)) {
            logger.error("RAS ID token has no acr claim; cannot verify assurance levels");
            return false;
        }
        int aal = extractAssuranceLevel(acr, "/assurance/aal/");
        int ial = extractAssuranceLevel(acr, "/assurance/ial/");
        if (aal < 2 || ial < 2) {
            logger.error("RAS LOGIN REJECTED ___ AAL {} IAL {} (require 2/2)", aal, ial);
            return false;
        }
        return true;
    }

    private int extractAssuranceLevel(String acr, String marker) {
        for (String uri : acr.trim().split("\\s+")) {
            int idx = uri.indexOf(marker);
            if (idx >= 0) {
                try {
                    return Integer.parseInt(uri.substring(idx + marker.length()).trim());
                } catch (NumberFormatException e) {
                    return -1;
                }
            }
        }
        return -1;
    }

    private RasIal2UserInfo parseUserinfo(JsonNode userinfo) {
        try {
            return objectMapper.treeToValue(userinfo, RasIal2UserInfo.class);
        } catch (JsonProcessingException e) {
            logger.error("Failed to map RAS userinfo response: {}", e.getClass().getSimpleName());
            return null;
        }
    }

    @Override
    public Optional<String> getAuthorizeUrl(String requestHost) {
        return Optional.of(rasOidcClient.buildAuthorizeUrl(requestHost));
    }

    // ------------------------------------------------------------------------------------------
    // Downstream pipeline — bodies identical to the Okta-brokered baseline except for the
    // parameter rename introspectResponse -> mergedClaims, txn replacing code in log correlation,
    // and the researcher_role addition in generateRasUserMetadata.
    // ------------------------------------------------------------------------------------------

    private Optional<Passport> extractAndVerifyPassport(JsonNode mergedClaims, User user) {
        Optional<Passport> rasPassport = this.rasPassPortService.extractPassport(mergedClaims);
        if (rasPassport.isEmpty()) {
            logger.info("LOGIN FAILED ___ NO RAS PASSPORT FOUND ___ USER: {}", user.getSubject());
            return Optional.empty();
        }

        if (rasPassPortService.isExpired(rasPassport.get())) {
            logger.error("validateRASPassport() LOGIN FAILED ___ PASSPORT IS EXPIRED ___ USER: {}", user.getSubject());
            return Optional.empty();
        }

        if (!rasPassport.get().getIss().equals(this.rasPassportIssuer)) {
            logger.error("validateRASPassport() LOGIN FAILED ___ PASSPORT ISSUER IS NOT CORRECT ___ USER: {} ___ " +
                         "EXPECTED ISSUER {} ___ ACTUAL ISSUER {}",
                    user.getSubject(), this.rasPassportIssuer, rasPassport.get().getIss());
            return Optional.empty();
        }
        return rasPassport;
    }

    protected User updateRasUserRoles(String txn, User user, Passport rasPassport) {
        logger.info("RAS PASSPORT FOUND ___ USER: {} ___ PASSPORT: {} ___ TXN {}", user.getSubject(), rasPassport, txn);
        Set<Optional<Ga4ghPassportV1>> ga4ghPassports = rasPassport.getGa4ghPassportV1().stream().map(JWTUtil::parseGa4ghPassportV1).filter(Optional::isPresent).collect(Collectors.toSet());
        Set<RasDbgapPermission> dbgapPermissions = this.rasPassPortService.ga4ghPassportToRasDbgapPermissions(ga4ghPassports);
        Set<String> dbgapRoleNames = this.roleService.getRoleNamesForDbgapPermissions(dbgapPermissions);
        user = userService.updateUserRoles(user, dbgapRoleNames);

        Set<String> userConsentStrings = dbgapPermissions.stream()
                .map(permission -> permission.getPhsId() + "." + permission.getConsentGroup()).collect(Collectors.toSet());
        user = userService.updateUserConsents(user, userConsentStrings);
        logger.debug("USER {} ROLES UPDATED {} ___ TXN {}",
                user.getSubject(),
                user.getRoles().stream().map(role -> role.getName().replace("MANAGED_", "")).toArray(),
                txn);
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

    private UserClaims buildUserClaims(User user, Passport rasPassport, RasIal2UserInfo rasUserinfo) {
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

        RasIal2UserInfo.FederatedIdentities federated = rasUserinfo.getFederatedIdentitiesIal2();
        if (federated != null) {
            try {
                userClaims.setFederated_sources(this.objectMapper.writeValueAsString(federated.getSources()));
            } catch (JsonProcessingException e) {
                logger.error("LOGIN FAILED ___ could not serialize federated_identities_ial2 for user {}", user.getSubject(), e);
                return null;
            }
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

            // researcher_role: comma-delimited role@institution pairs, eRA logins only. Non-blocking.
            if (StringUtils.isNotBlank(rasUserinfo.getResearcherRole())) {
                objectNode.put("researcher_role", rasUserinfo.getResearcherRole());
            }
        }

        return objectNode;
    }

    private void setUserPassport(String txn, JsonNode mergedClaims, User user) {
        String passport = mergedClaims.get("passport_jwt_v11").toString();
        user.setPassport(passport);
        userService.save(user);
        logger.info("RAS PASSPORT SUCCESSFULLY ADDED TO USER: {} ___ TXN {}", user.getSubject(), txn);
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
