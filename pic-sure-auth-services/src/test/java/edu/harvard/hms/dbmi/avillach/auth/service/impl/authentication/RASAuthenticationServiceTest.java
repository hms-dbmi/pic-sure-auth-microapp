package edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.harvard.hms.dbmi.avillach.auth.entity.Connection;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.entity.UserClaims;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasOidcTokens;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.*;
import edu.harvard.hms.dbmi.avillach.auth.utils.RasTestFixtures;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class RASAuthenticationServiceTest {

    private static final String HOST = "picsure.example.org";
    private static final String ACR_IAL2 = "https://stsstg.nih.gov/assurance/aal/2 https://stsstg.nih.gov/assurance/ial/2";
    private static final String ACR_IAL1 = "https://stsstg.nih.gov/assurance/aal/2 https://stsstg.nih.gov/assurance/ial/1";
    private static final String ACR_AAL1 = "https://stsstg.nih.gov/assurance/aal/1 https://stsstg.nih.gov/assurance/ial/2";

    private final ObjectMapper objectMapper = new ObjectMapper();

    private UserService userService;
    private RoleService roleService;
    private RASPassPortService rasPassPortService;
    private ConnectionWebService connectionService;
    private CacheEvictionService cacheEvictionService;
    private RasOidcClient rasOidcClient;
    private OidcFlowStateStore stateStore;
    private Connection rasConnection;
    private User testUser;

    @BeforeEach
    public void setUp() {
        userService = mock(UserService.class);
        roleService = mock(RoleService.class);
        // Real passport logic: extractPassport/isExpired/permission mapping run for real.
        rasPassPortService = new RASPassPortService(mock(edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil.class),
                userService, "https://stsstg.nih.gov", mock(CacheEvictionService.class), null);
        connectionService = mock(ConnectionWebService.class);
        cacheEvictionService = mock(CacheEvictionService.class);
        rasOidcClient = mock(RasOidcClient.class);
        stateStore = new OidcFlowStateStore();

        rasConnection = new Connection();
        rasConnection.setLabel("RAS");
        rasConnection.setSubPrefix("okta-ras|");
        when(connectionService.getConnectionByLabel("RAS")).thenReturn(rasConnection);

        testUser = new User();
        testUser.setUuid(UUID.randomUUID());
        testUser.setSubject("okta-ras|janeresearcher@era.nih.gov");
        testUser.setEmail("jane.researcher@example.org");
        testUser.setRoles(new HashSet<>());
        when(userService.createRasUser(any(edu.harvard.hms.dbmi.avillach.auth.model.ras.RasIal2UserInfo.class), eq(rasConnection)))
                .thenReturn(Optional.of(testUser));
        when(userService.updateUserRoles(any(User.class), anySet())).thenAnswer(inv -> inv.getArgument(0));
        when(userService.updateUserConsents(any(User.class), anySet())).thenAnswer(inv -> inv.getArgument(0));
        when(userService.addRoleClaims(any(User.class))).thenReturn(List.of());
        when(userService.getUserProfileResponse(any(UserClaims.class))).thenReturn(new HashMap<>(Map.of(
                "token", "psama-jwt", "userId", "okta-ras|janeresearcher@era.nih.gov")));
        when(roleService.getRoleNamesForDbgapPermissions(anySet())).thenReturn(Set.of("MANAGED_phs000007_c1"));
    }

    private RASAuthenticationService newService(boolean enforceIal2) {
        return new RASAuthenticationService(userService, roleService, rasPassPortService,
                connectionService, cacheEvictionService, rasOidcClient, stateStore,
                true, enforceIal2, RasTestFixtures.RAS_ISSUER);
    }

    private Claims idTokenClaims(String acr) {
        return Jwts.claims()
                .subject("RAS-SUB-0123456789abcdef")
                .issuer(RasTestFixtures.RAS_ISSUER)
                .add("acr", acr)
                .add("txn", "txn-test-0001")
                .add("nonce", "nonce-1")
                .build();
    }

    /** Wires the mocked RasOidcClient for a successful flow over the given userinfo JSON. */
    private Map<String, String> primeSuccessfulFlow(String userinfoJson, String acr) throws Exception {
        String state = stateStore.storeNewFlow("nonce-1", null);
        JsonNode userinfo = objectMapper.readTree(userinfoJson);
        Claims claims = idTokenClaims(acr);

        when(rasOidcClient.exchangeCode(eq("the-code"), eq(HOST), isNull()))
                .thenReturn(new RasOidcTokens("AT", "IDT", "RT"));
        when(rasOidcClient.validateIdToken(eq("IDT"), eq("nonce-1"))).thenReturn(Optional.of(claims));
        when(rasOidcClient.fetchUserinfo(eq("AT"))).thenReturn(userinfo);
        when(rasOidcClient.mergeClaims(eq(userinfo), eq(claims))).thenAnswer(inv -> {
            ObjectNode merged = ((JsonNode) inv.getArgument(0)).deepCopy();
            merged.put("sub", claims.getSubject());
            merged.put("acr", acr);
            merged.put("txn", "txn-test-0001");
            merged.put("iss", claims.getIssuer());
            return merged;
        });
        return new HashMap<>(Map.of("code", "the-code", "state", state));
    }

    @Test
    public void authenticate_fullPipeline_producesSameDownstreamEffectsAsOktaFlow() throws Exception {
        Map<String, String> authRequest = primeSuccessfulFlow(RasTestFixtures.fullUserinfoJson(), ACR_IAL2);

        HashMap<String, String> response = newService(true).authenticate(authRequest, HOST);

        assertNotNull(response);
        assertEquals("psama-jwt", response.get("token"));
        assertEquals("IDT", response.get("idToken"), "RAS ID token replaces oktaIdToken");
        assertFalse(response.containsKey("oktaIdToken"));

        // Same dbGaP-permission-to-role mapping as the Okta-brokered flow.
        verify(userService).updateUserRoles(any(User.class), eq(Set.of("MANAGED_phs000007_c1")));
        verify(userService).updateUserConsents(any(User.class), eq(Set.of("phs000007.c1")));

        // Passport stored on the user entity.
        assertNotNull(testUser.getPassport());

        // generalMetadata preserved + extended: idp/sub/email as before, researcher_role and
        // federated identities from userinfo.
        JsonNode metadata = objectMapper.readTree(testUser.getGeneralMetadata());
        assertEquals("RAS", metadata.get("idp").asText());
        assertEquals("okta-ras|janeresearcher@era.nih.gov", metadata.get("sub").asText());
        assertEquals("janeresearcher@era.nih.gov", metadata.get("default_identity").asText());
        assertEquals("jane@login.gov", metadata.get("authenticated_identity").asText());
        assertEquals("Principal Investigator@Harvard Medical School,Researcher@Broad Institute",
                metadata.get("researcher_role").asText());

        // UserClaims carry the same RAS-specific fields as before.
        ArgumentCaptor<UserClaims> userClaims = ArgumentCaptor.forClass(UserClaims.class);
        verify(userService).getUserProfileResponse(userClaims.capture());
        assertEquals("janeresearcher@era.nih.gov", userClaims.getValue().getPreferred_username());
        assertEquals("janeresearcher", userClaims.getValue().getUserid());
        assertEquals("RAS", userClaims.getValue().getIdp());
        // buildUserClaims sets era_commons_id from federated_identities_ial2.identities.era.userid.
        assertEquals("janeresearcher", userClaims.getValue().getEra_commons_id());
        assertNotNull(userClaims.getValue().getFederated_sources(), "federated sources serialized into claims");
    }

    @Test
    public void authenticate_rejectsMissingCodeOrState() {
        RASAuthenticationService service = newService(true);
        assertNull(service.authenticate(Map.of("state", "s-only"), HOST));
        assertNull(service.authenticate(Map.of("code", "c-only"), HOST));
        verifyNoInteractions(rasOidcClient);
    }

    @Test
    public void authenticate_rejectsUnknownOrReplayedState() throws Exception {
        Map<String, String> authRequest = primeSuccessfulFlow(RasTestFixtures.fullUserinfoJson(), ACR_IAL2);
        authRequest.put("state", "forged-state");

        assertNull(newService(true).authenticate(authRequest, HOST));
        verify(rasOidcClient, never()).exchangeCode(anyString(), anyString(), any());
    }

    @Test
    public void authenticate_rejectsFailedTokenExchange() throws Exception {
        Map<String, String> authRequest = primeSuccessfulFlow(RasTestFixtures.fullUserinfoJson(), ACR_IAL2);
        when(rasOidcClient.exchangeCode(anyString(), anyString(), any())).thenReturn(null);

        assertNull(newService(true).authenticate(authRequest, HOST));
        verify(rasOidcClient, never()).fetchUserinfo(anyString());
    }

    @Test
    public void authenticate_rejectsInvalidIdToken() throws Exception {
        Map<String, String> authRequest = primeSuccessfulFlow(RasTestFixtures.fullUserinfoJson(), ACR_IAL2);
        when(rasOidcClient.validateIdToken(anyString(), anyString())).thenReturn(Optional.empty());

        assertNull(newService(true).authenticate(authRequest, HOST));
        verify(rasOidcClient, never()).fetchUserinfo(anyString());
    }

    @Test
    public void authenticate_rejectsIal1WhenEnforced() throws Exception {
        Map<String, String> authRequest = primeSuccessfulFlow(RasTestFixtures.fullUserinfoJson(), ACR_IAL1);

        assertNull(newService(true).authenticate(authRequest, HOST));
        verify(rasOidcClient, never()).fetchUserinfo(anyString());
    }

    @Test
    public void authenticate_rejectsAal1WhenEnforced() throws Exception {
        Map<String, String> authRequest = primeSuccessfulFlow(RasTestFixtures.fullUserinfoJson(), ACR_AAL1);

        assertNull(newService(true).authenticate(authRequest, HOST));
        verify(rasOidcClient, never()).fetchUserinfo(anyString());
    }

    @Test
    public void authenticate_acceptsIal1WhenEnforcementDisabled() throws Exception {
        Map<String, String> authRequest = primeSuccessfulFlow(RasTestFixtures.fullUserinfoJson(), ACR_IAL1);

        assertNotNull(newService(false).authenticate(authRequest, HOST));
    }

    @Test
    public void authenticate_failsGracefullyWithoutPassport_noException() throws Exception {
        // Google-style IDP: no passport claim at all. Login must fail cleanly (null), not throw.
        Map<String, String> authRequest = primeSuccessfulFlow(
                RasTestFixtures.userinfoJson("ras-userinfo-no-passport.json", null), ACR_IAL2);

        assertNull(newService(true).authenticate(authRequest, HOST));
    }

    @Test
    public void authenticate_succeedsWithoutFederatedOrResearcherClaims() throws Exception {
        // Userinfo with passport but neither federated_identities_ial2 nor researcher_role:
        // processing of those claims is non-blocking.
        long exp = java.time.Instant.now().getEpochSecond() + 3600;
        String passport = RasTestFixtures.passportJwt(RasTestFixtures.RAS_ISSUER, exp,
                List.of(RasTestFixtures.dbgapVisaJwt(exp)));
        String userinfo = """
                {"sub":"RAS-SUB-0123456789abcdef","preferred_username":"plain@era.nih.gov","userid":"plain",
                 "email":"plain@example.org","passport_jwt_v11":"%s"}""".formatted(passport);
        Map<String, String> authRequest = primeSuccessfulFlow(userinfo, ACR_IAL2);

        assertNotNull(newService(true).authenticate(authRequest, HOST));
    }

    @Test
    public void authenticate_eraShapedUserinfo_researcherRoleWithoutIal2Block() throws Exception {
        // Realistic direct-eRA shape: researcher_role present, NO federated_identities_ial2.
        long exp = java.time.Instant.now().getEpochSecond() + 3600;
        String passport = RasTestFixtures.passportJwt(RasTestFixtures.RAS_ISSUER, exp,
                List.of(RasTestFixtures.dbgapVisaJwt(exp)));
        String userinfo = """
                {"sub":"RAS-SUB-0123456789abcdef","preferred_username":"erauser@era.nih.gov","userid":"erauser",
                 "email":"era@example.org","researcher_role":"Principal Investigator@Yale",
                 "passport_jwt_v11":"%s"}""".formatted(passport);
        Map<String, String> authRequest = primeSuccessfulFlow(userinfo, ACR_IAL2);

        HashMap<String, String> response = newService(true).authenticate(authRequest, HOST);

        assertNotNull(response);
        JsonNode metadata = objectMapper.readTree(testUser.getGeneralMetadata());
        assertEquals("Principal Investigator@Yale", metadata.get("researcher_role").asText());
        assertNull(metadata.get("default_identity"), "no federated block -> no federated metadata");
    }

    @Test
    public void authenticate_rejectsWrongPassportIssuer() throws Exception {
        long exp = java.time.Instant.now().getEpochSecond() + 3600;
        String passport = RasTestFixtures.passportJwt("https://wrong-issuer.example.com", exp,
                List.of(RasTestFixtures.dbgapVisaJwt(exp)));
        Map<String, String> authRequest = primeSuccessfulFlow(
                RasTestFixtures.userinfoJson("ras-userinfo-full.json", passport), ACR_IAL2);

        assertNull(newService(true).authenticate(authRequest, HOST));
    }

    // ------------------------------------------------------------------
    // New tests: OIDC Core 5.3.2 sub check, state single-use, expired passport
    // ------------------------------------------------------------------

    private static final SecretKey TEST_KEY =
            Keys.hmacShaKeyFor("test-signing-key-test-signing-key-test!!".getBytes(StandardCharsets.UTF_8));

    /** Builds an expired passport JWT with both exp and iat in the past. */
    private String expiredPassportJwt() {
        long now = Instant.now().getEpochSecond();
        long exp = now - 3600;
        long iat = now - 7200;
        long visaExp = now - 3600;
        String visaJwt = Jwts.builder().claims(Map.of(
                "iss", RasTestFixtures.RAS_ISSUER,
                "sub", "RAS-SUB-0123456789abcdef",
                "iat", iat,
                "exp", visaExp,
                "jti", "visa-expired-1",
                "txn", "txn-test-0001",
                "ga4gh_visa_v1", Map.of(
                        "type", "https://ras.nih.gov/visas/v1.1",
                        "asserted", iat,
                        "value", "https://stsstg.nih.gov/passport/dbgap/v1.1",
                        "source", "https://ncbi.nlm.nih.gov/gap",
                        "by", "dac"),
                "ras_dbgap_permissions", List.of(Map.of(
                        "consent_name", "General Research Use",
                        "phs_id", RasTestFixtures.DBGAP_PHS_ID,
                        "version", "v1",
                        "participant_set", "p1",
                        "consent_group", RasTestFixtures.DBGAP_CONSENT_GROUP,
                        "role", "pi",
                        "expiration", visaExp)))).signWith(TEST_KEY).compact();
        return Jwts.builder().claims(Map.of(
                "sub", "RAS-SUB-0123456789abcdef",
                "jti", "passport-expired-1",
                "scope", "openid ga4gh_passport_v1",
                "txn", "txn-test-0001",
                "iss", RasTestFixtures.RAS_ISSUER,
                "iat", iat,
                "exp", exp,
                "ga4gh_passport_v1", List.of(visaJwt))).signWith(TEST_KEY).compact();
    }

    @Test
    public void authenticate_rejectsUserinfoSubMismatch() throws Exception {
        Map<String, String> authRequest = primeSuccessfulFlow(RasTestFixtures.fullUserinfoJson(), ACR_IAL2);
        // Re-stub fetchUserinfo to return a userinfo with a different sub.
        JsonNode mismatchedUserinfo = objectMapper.readTree(
                "{\"sub\":\"DIFFERENT-SUB\",\"preferred_username\":\"x@era.nih.gov\"," +
                "\"userid\":\"x\",\"email\":\"x@example.org\"}");
        when(rasOidcClient.fetchUserinfo(anyString())).thenReturn(mismatchedUserinfo);

        assertNull(newService(true).authenticate(authRequest, HOST));
        verify(userService, never()).createRasUser(any(), any());
    }

    @Test
    public void authenticate_stateIsSingleUse_trueReplayRejected() throws Exception {
        Map<String, String> authRequest = primeSuccessfulFlow(RasTestFixtures.fullUserinfoJson(), ACR_IAL2);
        RASAuthenticationService service = newService(true);

        // First attempt succeeds.
        assertNotNull(service.authenticate(new HashMap<>(authRequest), HOST));

        // Second attempt with the same state is rejected (state already consumed).
        assertNull(service.authenticate(new HashMap<>(authRequest), HOST));

        // exchangeCode was only called once — the replay never reached it.
        verify(rasOidcClient, times(1)).exchangeCode(anyString(), anyString(), any());
    }

    @Test
    public void authenticate_stateBurnedWhenExchangeFails_retryRejectedAtStateCheck() throws Exception {
        Map<String, String> authRequest = primeSuccessfulFlow(RasTestFixtures.fullUserinfoJson(), ACR_IAL2);
        when(rasOidcClient.exchangeCode(anyString(), anyString(), any())).thenReturn(null);
        RASAuthenticationService service = newService(true);

        // First attempt: state consumed, exchange fails → null.
        assertNull(service.authenticate(new HashMap<>(authRequest), HOST));

        // Second attempt: state already consumed → dies at state check, exchangeCode not called again.
        assertNull(service.authenticate(new HashMap<>(authRequest), HOST));

        verify(rasOidcClient, times(1)).exchangeCode(anyString(), anyString(), any());
    }

    @Test
    public void authenticate_rejectsExpiredPassport() throws Exception {
        String expiredPassport = expiredPassportJwt();
        String userinfoJson = String.format(
                "{\"sub\":\"RAS-SUB-0123456789abcdef\",\"preferred_username\":\"x@era.nih.gov\"," +
                "\"userid\":\"x\",\"email\":\"x@example.org\",\"passport_jwt_v11\":\"%s\"}", expiredPassport);
        Map<String, String> authRequest = primeSuccessfulFlow(userinfoJson, ACR_IAL2);

        assertNull(newService(true).authenticate(authRequest, HOST));
    }

    @Test
    public void validateAssuranceLevels_parsesRealisticAcrStrings() {
        RASAuthenticationService service = newService(true);
        assertTrue(service.validateAssuranceLevels(ACR_IAL2));
        assertFalse(service.validateAssuranceLevels(ACR_IAL1));
        assertFalse(service.validateAssuranceLevels(ACR_AAL1));
        assertFalse(service.validateAssuranceLevels(null));
        assertFalse(service.validateAssuranceLevels(""));
        assertFalse(service.validateAssuranceLevels("https://stsstg.nih.gov/assurance/aal/2"), "missing ial");

        RASAuthenticationService lenient = newService(false);
        assertTrue(lenient.validateAssuranceLevels(ACR_IAL1));
        assertTrue(lenient.validateAssuranceLevels(null));
    }

    @Test
    public void getAuthorizeUrl_delegatesToOidcClient() {
        when(rasOidcClient.buildAuthorizeUrl(HOST)).thenReturn("https://stsstg.nih.gov/auth/oauth/v2/authorize?x=y");
        assertEquals(Optional.of("https://stsstg.nih.gov/auth/oauth/v2/authorize?x=y"),
                newService(true).getAuthorizeUrl(HOST));
    }

    @Test
    public void getProviderAndIsEnabled_unchangedContract() {
        RASAuthenticationService service = newService(true);
        assertEquals("ras", service.getProvider());
        assertTrue(service.isEnabled());
    }
}
