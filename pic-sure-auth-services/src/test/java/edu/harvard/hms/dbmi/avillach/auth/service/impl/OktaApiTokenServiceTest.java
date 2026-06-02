package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;

import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

public class OktaApiTokenServiceTest {

    private RestClientUtil restClientUtil;
    private static String privateKeyBase64;

    private static final String MGMT_URL = "https://example.okta.com";
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
    }

    private OktaApiTokenService newService() {
        return new OktaApiTokenService(MGMT_URL, CLIENT_ID, privateKeyBase64, SCOPE, restClientUtil);
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
        OktaApiTokenService svc = new OktaApiTokenService(MGMT_URL, CLIENT_ID, "false", SCOPE, restClientUtil);

        assertNull(svc.getAccessToken());
        verify(restClientUtil, never()).retrievePostResponse(anyString(), any(HttpHeaders.class), anyString());
    }
}
