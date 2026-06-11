package edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication;

import edu.harvard.hms.dbmi.avillach.auth.entity.Connection;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.entity.UserClaims;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasIal2UserInfo;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.*;
import edu.harvard.hms.dbmi.avillach.auth.utils.RasTestFixtures;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import edu.harvard.hms.dbmi.avillach.auth.utils.RsaJwksTestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.client.ExpectedCount.manyTimes;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * End-to-end direct-RAS login over a real HTTP layer: real RestTemplate/RestClientUtil, real
 * RasOidcClient + OidcIdTokenValidator + OidcFlowStateStore + RASAuthenticationService, with every
 * RAS endpoint stubbed by MockRestServiceServer and only the DB-backed services mocked. No Okta.
 */
public class RasDirectFlowIntegrationTest {

    private static final String BASE = "https://stsstg.nih.gov";
    private static final String CLIENT_ID = "picsure-staging-client";
    private static final String HOST = "picsure.example.org";

    private MockRestServiceServer mockServer;
    private RASAuthenticationService service;
    private UserService userService;
    private User testUser;
    private KeyPair keyPair;

    @BeforeEach
    public void setUp() {
        RestTemplate restTemplate = new RestTemplate();
        mockServer = MockRestServiceServer.bindTo(restTemplate).ignoreExpectOrder(true).build();
        RestClientUtil restClientUtil = new RestClientUtil(restTemplate);

        keyPair = RsaJwksTestSupport.generateKeyPair();
        OidcFlowStateStore stateStore = new OidcFlowStateStore();
        RasOidcClient oidcClient = new RasOidcClient(restClientUtil, new OidcIdTokenValidator(restClientUtil),
                stateStore, BASE, CLIENT_ID, "secret", "", BASE);

        userService = mock(UserService.class);
        RoleService roleService = mock(RoleService.class);
        ConnectionWebService connectionService = mock(ConnectionWebService.class);
        CacheEvictionService cacheEvictionService = mock(CacheEvictionService.class);
        RASPassPortService passPortService = new RASPassPortService(restClientUtil, userService, BASE,
                cacheEvictionService, null);

        Connection rasConnection = new Connection();
        rasConnection.setLabel("RAS");
        rasConnection.setSubPrefix("okta-ras|");
        when(connectionService.getConnectionByLabel("RAS")).thenReturn(rasConnection);

        testUser = new User();
        testUser.setUuid(UUID.randomUUID());
        testUser.setSubject("okta-ras|janeresearcher@era.nih.gov");
        testUser.setEmail("jane.researcher@example.org");
        testUser.setRoles(new HashSet<>());
        when(userService.createRasUser(any(RasIal2UserInfo.class), eq(rasConnection)))
                .thenReturn(Optional.of(testUser));
        when(userService.updateUserRoles(any(), anySet())).thenAnswer(inv -> inv.getArgument(0));
        when(userService.updateUserConsents(any(), anySet())).thenAnswer(inv -> inv.getArgument(0));
        when(userService.addRoleClaims(any())).thenReturn(List.of());
        when(userService.getUserProfileResponse(any(UserClaims.class)))
                .thenReturn(new HashMap<>(Map.of("token", "psama-jwt", "userId", testUser.getSubject())));
        when(roleService.getRoleNamesForDbgapPermissions(anySet())).thenReturn(Set.of("MANAGED_phs000007_c1"));

        service = new RASAuthenticationService(userService, roleService, passPortService,
                connectionService, cacheEvictionService, oidcClient, stateStore, true, true, BASE);
    }

    @Test
    public void endToEnd_authorizeUrlThroughPicsureJwt_noOktaInvolved() {
        // All MockRestServiceServer expectations must be registered BEFORE the first actual request
        // (getAuthorizeUrl triggers discovery). The token response's id_token depends on the flow's
        // nonce, which is only known after the authorize URL is built, so the token endpoint responds
        // lazily: it reads the captured nonce and signs the ID token at request time.
        String[] capturedNonce = new String[1];
        String[] signedIdToken = new String[1];

        // --- Stub the RAS endpoints the flow touches ---
        mockServer.expect(manyTimes(), requestTo(BASE + "/.well-known/openid-configuration"))
                .andRespond(withSuccess("""
                        {"issuer":"%s",
                         "authorization_endpoint":"%s/auth/oauth/v2/authorize",
                         "token_endpoint":"%s/auth/oauth/v2/token",
                         "jwks_uri":"%s/openid/connect/jwks.json"}""".formatted(BASE, BASE, BASE, BASE),
                        MediaType.APPLICATION_JSON));
        mockServer.expect(manyTimes(), requestTo(BASE + "/openid/connect/jwks.json"))
                .andRespond(withSuccess(RsaJwksTestSupport.jwksJson("kid-1", (RSAPublicKey) keyPair.getPublic()),
                        MediaType.APPLICATION_JSON));

        // 2. RAS redirects back with a code; PSAMA exchanges it. The signed ID token's sub MUST equal
        //    the userinfo sub (RAS-SUB-0123456789abcdef) per the OIDC 5.3.2 check in the pipeline.
        mockServer.expect(manyTimes(), requestTo(BASE + "/auth/oauth/v2/token"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("Authorization", org.hamcrest.Matchers.startsWith("Basic ")))
                .andRespond(request -> {
                    // Sign the ID token lazily so it carries this flow's actual nonce.
                    String idToken = RsaJwksTestSupport.signedJwt(keyPair, "kid-1", BASE, CLIENT_ID,
                            "RAS-SUB-0123456789abcdef",
                            Map.of("nonce", capturedNonce[0],
                                   "acr", "https://stsstg.nih.gov/assurance/aal/2 https://stsstg.nih.gov/assurance/ial/2",
                                   "txn", "txn-test-0001"),
                            Instant.now().plusSeconds(3600));
                    signedIdToken[0] = idToken;
                    String body = """
                            {"access_token":"AT-1","id_token":"%s","refresh_token":"RT-1","expires_in":1800}"""
                            .formatted(idToken);
                    MockClientHttpResponse resp = new MockClientHttpResponse(
                            body.getBytes(StandardCharsets.UTF_8), org.springframework.http.HttpStatus.OK);
                    resp.getHeaders().setContentType(MediaType.APPLICATION_JSON);
                    return resp;
                });
        mockServer.expect(manyTimes(), requestTo(BASE + "/openid/connect/v1.1/userinfo"))
                .andExpect(header("Authorization", "Bearer AT-1"))
                .andRespond(withSuccess(RasTestFixtures.fullUserinfoJson(), MediaType.APPLICATION_JSON));

        // 1. PSAMA builds the authorize URL (what GET /authentication/ras/authorize-url returns).
        String authorizeUrl = service.getAuthorizeUrl(HOST).orElseThrow();
        assertTrue(authorizeUrl.startsWith(BASE + "/auth/oauth/v2/authorize?response_type=code"));
        String state = queryParam(authorizeUrl, "state");
        capturedNonce[0] = queryParam(authorizeUrl, "nonce");

        // 3. Callback: code + state into authenticate().
        HashMap<String, String> response = service.authenticate(Map.of("code", "auth-code-1", "state", state), HOST);

        assertNotNull(response, "end-to-end login should succeed against stubbed RAS");
        assertEquals("psama-jwt", response.get("token"));
        assertEquals(signedIdToken[0], response.get("idToken"));
        assertFalse(response.containsKey("oktaIdToken"));
        verify(userService).updateUserRoles(any(), eq(Set.of("MANAGED_phs000007_c1")));
        assertNotNull(testUser.getPassport(), "passport persisted on the user entity");
    }

    private static String queryParam(String url, String name) {
        for (String pair : url.substring(url.indexOf('?') + 1).split("&")) {
            if (pair.startsWith(name + "=")) {
                return URLDecoder.decode(pair.substring(name.length() + 1), StandardCharsets.UTF_8);
            }
        }
        throw new AssertionError("missing query param " + name);
    }
}
