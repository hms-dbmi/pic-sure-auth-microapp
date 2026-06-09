package edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasOidcTokens;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class RasOidcClientTest {

    private static final String BASE = "https://stsstg.nih.gov";
    private static final String CLIENT_ID = "picsure-client";
    private static final String CLIENT_SECRET = "shh";
    private static final String ISSUER = "https://stsstg.nih.gov";
    private static final String HOST = "picsure.example.org";

    private static final String DISCOVERY_JSON = """
            {
              "issuer": "https://stsstg.nih.gov",
              "authorization_endpoint": "https://stsstg.nih.gov/auth/oauth/v2/authorize",
              "token_endpoint": "https://stsstg.nih.gov/auth/oauth/v2/token",
              "userinfo_endpoint": "https://stsstg.nih.gov/openid/connect/v1/userinfo",
              "jwks_uri": "https://stsstg.nih.gov/openid/connect/jwks.json"
            }""";

    private static final String DISCOVERY_JSON_WITH_PKCE = """
            {
              "authorization_endpoint": "https://stsstg.nih.gov/auth/oauth/v2/authorize",
              "token_endpoint": "https://stsstg.nih.gov/auth/oauth/v2/token",
              "jwks_uri": "https://stsstg.nih.gov/openid/connect/jwks.json",
              "code_challenge_methods_supported": ["S256"]
            }""";

    private RestClientUtil restClientUtil;
    private OidcIdTokenValidator idTokenValidator;
    private OidcFlowStateStore stateStore;

    @BeforeEach
    public void setUp() {
        restClientUtil = mock(RestClientUtil.class);
        idTokenValidator = mock(OidcIdTokenValidator.class);
        stateStore = new OidcFlowStateStore();
    }

    private RasOidcClient newClient() {
        return new RasOidcClient(restClientUtil, idTokenValidator, stateStore,
                BASE, CLIENT_ID, CLIENT_SECRET, "", ISSUER);
    }

    private void stubDiscovery(String json) {
        when(restClientUtil.retrieveGetResponse(eq(BASE + "/.well-known/openid-configuration"), any(HttpHeaders.class)))
                .thenReturn(ResponseEntity.ok(json));
    }

    @Test
    public void buildAuthorizeUrl_containsAllOidcParamsAndStoresFlow() {
        stubDiscovery(DISCOVERY_JSON);
        RasOidcClient client = newClient();

        String url = client.buildAuthorizeUrl(HOST);

        assertTrue(url.startsWith("https://stsstg.nih.gov/auth/oauth/v2/authorize?response_type=code"));
        assertTrue(url.contains("&client_id=" + CLIENT_ID));
        assertTrue(url.contains("&redirect_uri=https%3A%2F%2Fpicsure.example.org%2Flogin%2Floading"));
        assertTrue(url.contains("&scope=openid+profile+email+ga4gh_passport_v1+researcher_role"
                + "+federated_identities_ial2+federated_identities+federated_sources"));
        assertTrue(url.contains("&state="));
        assertTrue(url.contains("&nonce="));
        assertFalse(url.contains("code_challenge"), "no PKCE when discovery does not advertise S256");

        String state = paramValue(url, "state");
        Optional<OidcFlowStateStore.FlowState> flow = stateStore.consume(state);
        assertTrue(flow.isPresent(), "authorize URL state must be stored for callback verification");
        assertEquals(paramValue(url, "nonce"), flow.get().nonce());
        assertNull(flow.get().codeVerifier());
    }

    @Test
    public void buildAuthorizeUrl_addsPkceWhenDiscoveryAdvertisesS256() {
        stubDiscovery(DISCOVERY_JSON_WITH_PKCE);
        RasOidcClient client = newClient();

        String url = client.buildAuthorizeUrl(HOST);

        assertTrue(url.contains("&code_challenge="));
        assertTrue(url.contains("&code_challenge_method=S256"));
        Optional<OidcFlowStateStore.FlowState> flow = stateStore.consume(paramValue(url, "state"));
        assertNotNull(flow.orElseThrow().codeVerifier(), "PKCE verifier must be stored with the flow");
    }

    @Test
    public void buildAuthorizeUrl_fallsBackToDocumentedPathsWhenDiscoveryFails() {
        when(restClientUtil.retrieveGetResponse(eq(BASE + "/.well-known/openid-configuration"), any(HttpHeaders.class)))
                .thenThrow(new RuntimeException("connection refused"));
        RasOidcClient client = newClient();

        String url = client.buildAuthorizeUrl(HOST);

        assertTrue(url.startsWith(BASE + "/auth/oauth/v2/authorize?response_type=code"));
    }

    @Test
    public void exchangeCode_postsFormEncodedExchangeWithBasicAuth() throws Exception {
        stubDiscovery(DISCOVERY_JSON);
        when(restClientUtil.retrievePostResponse(eq(BASE + "/auth/oauth/v2/token"), any(HttpHeaders.class), anyString()))
                .thenReturn(ResponseEntity.ok(
                        "{\"access_token\":\"AT\",\"id_token\":\"IDT\",\"refresh_token\":\"RT\",\"expires_in\":1800}"));
        RasOidcClient client = newClient();

        RasOidcTokens tokens = client.exchangeCode("the-code", HOST, null);

        assertEquals("AT", tokens.accessToken());
        assertEquals("IDT", tokens.idToken());
        assertEquals("RT", tokens.refreshToken());

        ArgumentCaptor<HttpHeaders> headers = ArgumentCaptor.forClass(HttpHeaders.class);
        ArgumentCaptor<String> body = ArgumentCaptor.forClass(String.class);
        verify(restClientUtil).retrievePostResponse(eq(BASE + "/auth/oauth/v2/token"), headers.capture(), body.capture());

        assertTrue(headers.getValue().getFirst("Authorization").startsWith("Basic "));
        assertEquals(MediaType.APPLICATION_FORM_URLENCODED, headers.getValue().getContentType());
        String decoded = URLDecoder.decode(body.getValue(), StandardCharsets.UTF_8);
        assertTrue(decoded.contains("grant_type=authorization_code"));
        assertTrue(decoded.contains("code=the-code"));
        assertTrue(decoded.contains("redirect_uri=https://picsure.example.org/login/loading"));
        assertFalse(decoded.contains("code_verifier"));
    }

    @Test
    public void exchangeCode_includesPkceVerifierWhenPresent() {
        stubDiscovery(DISCOVERY_JSON);
        when(restClientUtil.retrievePostResponse(anyString(), any(HttpHeaders.class), anyString()))
                .thenReturn(ResponseEntity.ok("{\"access_token\":\"AT\",\"id_token\":\"IDT\"}"));
        RasOidcClient client = newClient();

        client.exchangeCode("c", HOST, "my-verifier");

        ArgumentCaptor<String> body = ArgumentCaptor.forClass(String.class);
        verify(restClientUtil).retrievePostResponse(anyString(), any(HttpHeaders.class), body.capture());
        assertTrue(body.getValue().contains("code_verifier=my-verifier"));
    }

    @Test
    public void exchangeCode_returnsNullOnMissingTokensOrHttpFailure() {
        stubDiscovery(DISCOVERY_JSON);
        when(restClientUtil.retrievePostResponse(anyString(), any(HttpHeaders.class), anyString()))
                .thenReturn(ResponseEntity.ok("{\"error\":\"invalid_grant\"}"));
        assertNull(newClient().exchangeCode("bad-code", HOST, null));

        reset(restClientUtil);
        stubDiscovery(DISCOVERY_JSON);
        when(restClientUtil.retrievePostResponse(anyString(), any(HttpHeaders.class), anyString()))
                .thenThrow(new RuntimeException("500"));
        assertNull(newClient().exchangeCode("any", HOST, null));
    }

    @Test
    public void validateIdToken_rejectsNonceMismatch() {
        stubDiscovery(DISCOVERY_JSON);
        Claims claims = mock(Claims.class);
        when(claims.get("nonce", String.class)).thenReturn("different-nonce");
        when(idTokenValidator.validate(eq("IDT"), anyString(), eq(ISSUER), eq(CLIENT_ID)))
                .thenReturn(Optional.of(claims));

        assertTrue(newClient().validateIdToken("IDT", "expected-nonce").isEmpty());
    }

    @Test
    public void validateIdToken_acceptsMatchingNonce() {
        stubDiscovery(DISCOVERY_JSON);
        Claims claims = mock(Claims.class);
        when(claims.get("nonce", String.class)).thenReturn("expected-nonce");
        when(idTokenValidator.validate(eq("IDT"), anyString(), eq(ISSUER), eq(CLIENT_ID)))
                .thenReturn(Optional.of(claims));

        assertTrue(newClient().validateIdToken("IDT", "expected-nonce").isPresent());
    }

    @Test
    public void fetchUserinfo_parsesJsonResponseAndUsesV11PathWithBearerToken() {
        stubDiscovery(DISCOVERY_JSON);
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.setContentType(MediaType.APPLICATION_JSON);
        when(restClientUtil.retrieveGetResponse(eq(BASE + "/openid/connect/v1.1/userinfo"), any(HttpHeaders.class)))
                .thenReturn(new ResponseEntity<>("{\"sub\":\"abc\",\"email\":\"a@b.org\"}", responseHeaders, org.springframework.http.HttpStatus.OK));

        JsonNode userinfo = newClient().fetchUserinfo("AT");

        assertEquals("abc", userinfo.get("sub").asText());

        ArgumentCaptor<HttpHeaders> sent = ArgumentCaptor.forClass(HttpHeaders.class);
        verify(restClientUtil).retrieveGetResponse(eq(BASE + "/openid/connect/v1.1/userinfo"), sent.capture());
        assertEquals("Bearer AT", sent.getValue().getFirst("Authorization"));
    }

    @Test
    public void fetchUserinfo_validatesSignedJwtResponse() {
        stubDiscovery(DISCOVERY_JSON);
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.setContentType(MediaType.parseMediaType("application/jwt"));
        when(restClientUtil.retrieveGetResponse(eq(BASE + "/openid/connect/v1.1/userinfo"), any(HttpHeaders.class)))
                .thenReturn(new ResponseEntity<>("signed.jwt.body", responseHeaders, org.springframework.http.HttpStatus.OK));

        Claims claims = io.jsonwebtoken.Jwts.claims().subject("abc").add("email", "a@b.org").build();
        when(idTokenValidator.validate(eq("signed.jwt.body"), anyString(), eq(ISSUER), eq(CLIENT_ID)))
                .thenReturn(Optional.of(claims));

        JsonNode userinfo = newClient().fetchUserinfo("AT");

        assertEquals("abc", userinfo.get("sub").asText());
        assertEquals("a@b.org", userinfo.get("email").asText());
    }

    @Test
    public void fetchUserinfo_returnsNullOnFailure() {
        stubDiscovery(DISCOVERY_JSON);
        when(restClientUtil.retrieveGetResponse(eq(BASE + "/openid/connect/v1.1/userinfo"), any(HttpHeaders.class)))
                .thenThrow(new RuntimeException("401"));
        assertNull(newClient().fetchUserinfo("expired-token"));
    }

    @Test
    public void mergeClaims_overlaysIdTokenClaimsOnUserinfo() throws Exception {
        stubDiscovery(DISCOVERY_JSON);
        ObjectNode userinfo = (ObjectNode) new ObjectMapper().readTree(
                "{\"sub\":\"userinfo-sub\",\"email\":\"a@b.org\",\"passport_jwt_v11\":\"PJ\"}");
        Claims idTokenClaims = io.jsonwebtoken.Jwts.claims()
                .subject("idtoken-sub")
                .issuer(ISSUER)
                .add("acr", "https://stsstg.nih.gov/assurance/aal/2 https://stsstg.nih.gov/assurance/ial/2")
                .add("txn", "txn-123")
                .build();

        ObjectNode merged = newClient().mergeClaims(userinfo, idTokenClaims);

        assertEquals("idtoken-sub", merged.get("sub").asText(), "ID token sub is authoritative");
        assertEquals("a@b.org", merged.get("email").asText(), "userinfo claims preserved");
        assertEquals("PJ", merged.get("passport_jwt_v11").asText());
        assertTrue(merged.get("acr").asText().contains("/assurance/ial/2"));
        assertEquals("txn-123", merged.get("txn").asText());
        assertEquals(ISSUER, merged.get("iss").asText());
    }

    private static String paramValue(String url, String name) {
        for (String pair : url.substring(url.indexOf('?') + 1).split("&")) {
            if (pair.startsWith(name + "=")) {
                return URLDecoder.decode(pair.substring(name.length() + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }
}
