package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;

import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class OktaApiTokenServiceTest {

    private RestClientUtil restClientUtil;
    private DpopProofService dpopProofService;
    private static String privateKeyBase64;

    private static final String MGMT_URL = "https://example.okta.com";
    private static final String TOKEN_URL = MGMT_URL + "/oauth2/v1/token";
    private static final String CLIENT_ID = "0oaApiClientId";
    private static final String SCOPE = "okta.idps.read";

    @BeforeAll
    public static void generateKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048); // RS256 requires >= 2048-bit keys; jjwt throws WeakKeyException otherwise
        privateKeyBase64 = Base64.getEncoder().encodeToString(kpg.generateKeyPair().getPrivate().getEncoded());
    }

    @BeforeEach
    public void setUp() {
        restClientUtil = mock(RestClientUtil.class);
        dpopProofService = mock(DpopProofService.class);
    }

    /** DPoP disabled: byte-for-byte today's behavior. */
    private OktaApiTokenService newService() {
        return new OktaApiTokenService(MGMT_URL, CLIENT_ID, privateKeyBase64, SCOPE, false, restClientUtil, dpopProofService);
    }

    private OktaApiTokenService newDpopService() {
        return new OktaApiTokenService(MGMT_URL, CLIENT_ID, privateKeyBase64, SCOPE, true, restClientUtil, dpopProofService);
    }

    private HttpClientErrorException nonceChallenge(HttpStatus status, String nonce) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("dpop-nonce", nonce);
        return HttpClientErrorException.create(status, status.getReasonPhrase(), headers, null, null);
    }

    @Test
    public void getAccessToken_mintsThenCaches() {
        when(restClientUtil.retrievePostResponse(anyString(), any(HttpHeaders.class), anyString()))
                .thenReturn(ResponseEntity.ok("{\"access_token\":\"tok1\",\"expires_in\":3600}"));
        OktaApiTokenService svc = newService();

        assertEquals("tok1", svc.getAccessToken());
        assertEquals("tok1", svc.getAccessToken());

        verify(restClientUtil, times(1)).retrievePostResponse(anyString(), any(HttpHeaders.class), anyString());
    }

    @Test
    public void getAccessToken_reMintsAfterExpiry() {
        when(restClientUtil.retrievePostResponse(anyString(), any(HttpHeaders.class), anyString()))
                .thenReturn(ResponseEntity.ok("{\"access_token\":\"tok1\",\"expires_in\":0}"))
                .thenReturn(ResponseEntity.ok("{\"access_token\":\"tok2\",\"expires_in\":0}"));
        OktaApiTokenService svc = newService();

        assertEquals("tok1", svc.getAccessToken());
        assertEquals("tok2", svc.getAccessToken());

        verify(restClientUtil, times(2)).retrievePostResponse(anyString(), any(HttpHeaders.class), anyString());
    }

    @Test
    public void getAccessToken_reMintsAfterInvalidate() {
        when(restClientUtil.retrievePostResponse(anyString(), any(HttpHeaders.class), anyString()))
                .thenReturn(ResponseEntity.ok("{\"access_token\":\"tok1\",\"expires_in\":3600}"))
                .thenReturn(ResponseEntity.ok("{\"access_token\":\"tok2\",\"expires_in\":3600}"));
        OktaApiTokenService svc = newService();

        assertEquals("tok1", svc.getAccessToken());
        svc.invalidate();
        assertEquals("tok2", svc.getAccessToken());

        verify(restClientUtil, times(2)).retrievePostResponse(anyString(), any(HttpHeaders.class), anyString());
    }

    @Test
    public void getAccessToken_returnsNull_onTokenEndpoint403() {
        when(restClientUtil.retrievePostResponse(anyString(), any(HttpHeaders.class), anyString()))
                .thenThrow(HttpClientErrorException.create(HttpStatus.FORBIDDEN, "Forbidden", HttpHeaders.EMPTY, null, null));
        OktaApiTokenService svc = newService();

        assertNull(svc.getAccessToken());
    }

    @Test
    public void getAccessToken_reMintsAfterFailure_doesNotPoisonCache() {
        when(restClientUtil.retrievePostResponse(anyString(), any(HttpHeaders.class), anyString()))
                .thenThrow(HttpClientErrorException.create(HttpStatus.FORBIDDEN, "Forbidden", HttpHeaders.EMPTY, null, null))
                .thenReturn(ResponseEntity.ok("{\"access_token\":\"tok1\",\"expires_in\":3600}"));
        OktaApiTokenService svc = newService();

        assertNull(svc.getAccessToken());          // 403 -> null, cache not poisoned
        assertEquals("tok1", svc.getAccessToken()); // next call re-mints successfully
    }

    @Test
    public void getAccessToken_returnsNull_whenPrivateKeyUnconfigured() {
        OktaApiTokenService svc = new OktaApiTokenService(MGMT_URL, CLIENT_ID, "false", SCOPE, false, restClientUtil, dpopProofService);

        assertNull(svc.getAccessToken());
        verify(restClientUtil, never()).retrievePostResponse(anyString(), any(HttpHeaders.class), anyString());
    }

    @Test
    public void getToken_bearerByDefault_whenDpopDisabled() {
        when(restClientUtil.retrievePostResponse(anyString(), any(HttpHeaders.class), anyString()))
                .thenReturn(ResponseEntity.ok("{\"access_token\":\"tok1\",\"expires_in\":3600}"));
        OktaApiTokenService svc = newService();

        OktaApiTokenService.OktaApiToken token = svc.getToken();
        assertEquals("tok1", token.value());
        assertFalse(token.dpopBound());
        verify(dpopProofService, never()).createProof(any(), any(), any(), any());
    }

    @Test
    public void getToken_sendsDpopProof_andMarksDpopBound_whenEnabled() {
        when(dpopProofService.createProof(eq("POST"), eq(TOKEN_URL), isNull(), isNull())).thenReturn("PROOF");
        when(restClientUtil.retrievePostResponse(anyString(), any(HttpHeaders.class), anyString()))
                .thenReturn(ResponseEntity.ok("{\"access_token\":\"tok1\",\"expires_in\":3600,\"token_type\":\"DPoP\"}"));
        OktaApiTokenService svc = newDpopService();

        OktaApiTokenService.OktaApiToken token = svc.getToken();
        assertEquals("tok1", token.value());
        assertTrue(token.dpopBound());

        ArgumentCaptor<HttpHeaders> headers = ArgumentCaptor.forClass(HttpHeaders.class);
        verify(restClientUtil).retrievePostResponse(eq(TOKEN_URL), headers.capture(), anyString());
        assertEquals("PROOF", headers.getValue().getFirst("DPoP"));
    }

    @Test
    public void getToken_retriesWithNonce_onTokenEndpointNonceChallenge() {
        when(dpopProofService.createProof(eq("POST"), eq(TOKEN_URL), isNull(), isNull())).thenReturn("P1");
        when(dpopProofService.createProof(eq("POST"), eq(TOKEN_URL), eq("TNONCE"), isNull())).thenReturn("P2");
        when(restClientUtil.retrievePostResponse(anyString(), any(HttpHeaders.class), anyString()))
                .thenThrow(nonceChallenge(HttpStatus.BAD_REQUEST, "TNONCE"))
                .thenReturn(ResponseEntity.ok("{\"access_token\":\"tok1\",\"expires_in\":3600,\"token_type\":\"DPoP\"}"));
        OktaApiTokenService svc = newDpopService();

        assertEquals("tok1", svc.getToken().value());
        verify(restClientUtil, times(2)).retrievePostResponse(anyString(), any(HttpHeaders.class), anyString());
        verify(dpopProofService).createProof("POST", TOKEN_URL, null, null);
        verify(dpopProofService).createProof("POST", TOKEN_URL, "TNONCE", null);
    }

    @Test
    public void getToken_dpopBoundFalse_whenServerReturnsBearer_evenIfEnabled() {
        when(dpopProofService.createProof(eq("POST"), eq(TOKEN_URL), isNull(), isNull())).thenReturn("PROOF");
        when(restClientUtil.retrievePostResponse(anyString(), any(HttpHeaders.class), anyString()))
                .thenReturn(ResponseEntity.ok("{\"access_token\":\"tok1\",\"expires_in\":3600,\"token_type\":\"Bearer\"}"));
        OktaApiTokenService svc = newDpopService();

        assertFalse(svc.getToken().dpopBound());
    }

    @Test
    public void getToken_doesNotRetry_whenDpopDisabledAndNonceHeaderPresent() {
        when(restClientUtil.retrievePostResponse(anyString(), any(HttpHeaders.class), anyString()))
                .thenThrow(nonceChallenge(HttpStatus.BAD_REQUEST, "TNONCE"));
        OktaApiTokenService svc = newService(); // DPoP disabled

        assertNull(svc.getToken());
        verify(restClientUtil, times(1)).retrievePostResponse(anyString(), any(HttpHeaders.class), anyString());
        verify(dpopProofService, never()).createProof(any(), any(), any(), any());
    }

    @Test
    public void getToken_doesNotRetryMoreThanOnce_onRepeatedNonceChallenge() {
        when(dpopProofService.createProof(eq("POST"), eq(TOKEN_URL), any(), isNull())).thenReturn("PROOF");
        when(restClientUtil.retrievePostResponse(anyString(), any(HttpHeaders.class), anyString()))
                .thenThrow(nonceChallenge(HttpStatus.BAD_REQUEST, "N1"))
                .thenThrow(nonceChallenge(HttpStatus.BAD_REQUEST, "N2"));
        OktaApiTokenService svc = newDpopService(); // DPoP enabled

        assertNull(svc.getToken());
        verify(restClientUtil, times(2)).retrievePostResponse(anyString(), any(HttpHeaders.class), anyString());
    }
}
