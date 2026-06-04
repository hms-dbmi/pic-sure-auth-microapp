package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class RasUserinfoServiceTest {

    private RestClientUtil restClientUtil;
    private OktaApiTokenService oktaApiTokenService;
    private DpopProofService dpopProofService;

    private static final String MGMT_URL = "https://example.okta.com";
    private static final String IDP_ID = "0oaIdpId";
    private static final String USERINFO_URI = "https://stsstg.nih.gov/openid/connect/v1.1/userinfo";
    private static final String OKTA_USER_ID = "00uUserId";

    private static final String TOKENS_RESPONSE =
            "[{\"id\":\"a\",\"tokenType\":\"urn:okta:params:oauth:token-type:id_token\",\"tokenAuthScheme\":\"Bearer\",\"token\":\"ID_TOKEN\"}," +
            "{\"id\":\"b\",\"tokenType\":\"urn:okta:params:oauth:token-type:access_token\",\"tokenAuthScheme\":\"Bearer\",\"token\":\"RAS_ACCESS_TOKEN\"}]";
    private static final String USERINFO_BODY =
            "{\"sub\":\"ras-sub\",\"federated_identities_ial2\":{\"nih\":{\"userid\":\"x\"}}}";

    @BeforeEach
    public void setUp() {
        restClientUtil = mock(RestClientUtil.class);
        oktaApiTokenService = mock(OktaApiTokenService.class);
        dpopProofService = mock(DpopProofService.class);
        when(oktaApiTokenService.getToken())
                .thenReturn(new OktaApiTokenService.OktaApiToken("OKTA_API_TOKEN", false));
    }

    private RasUserinfoService newService(boolean enabled) {
        return new RasUserinfoService(enabled, MGMT_URL, IDP_ID, USERINFO_URI, restClientUtil, oktaApiTokenService, dpopProofService);
    }

    private HttpClientErrorException httpError(HttpStatus status) {
        return HttpClientErrorException.create(status, status.getReasonPhrase(), HttpHeaders.EMPTY, null, null);
    }

    private HttpClientErrorException dpopNonce(HttpStatus status, String nonce) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("dpop-nonce", nonce);
        return HttpClientErrorException.create(status, status.getReasonPhrase(), headers, null, null);
    }

    @Test
    public void fetchUserinfo_success_returnsParsedBody() {
        when(restClientUtil.retrieveGetResponse(contains("/credentials/tokens"), any(HttpHeaders.class)))
                .thenReturn(ResponseEntity.ok(TOKENS_RESPONSE));
        when(restClientUtil.retrieveGetResponse(eq(USERINFO_URI), any(HttpHeaders.class)))
                .thenReturn(ResponseEntity.ok(USERINFO_BODY));

        JsonNode result = newService(true).fetchUserinfo(OKTA_USER_ID);

        assertEquals("x", result.get("federated_identities_ial2").get("nih").get("userid").asText());
    }

    @Test
    public void fetchUserinfo_returnsNull_whenDisabled() {
        JsonNode result = newService(false).fetchUserinfo(OKTA_USER_ID);

        assertNull(result);
        verifyNoInteractions(restClientUtil);
        verifyNoInteractions(oktaApiTokenService);
    }

    @Test
    public void fetchUserinfo_returnsNull_onTokenEndpoint403() {
        when(restClientUtil.retrieveGetResponse(contains("/credentials/tokens"), any(HttpHeaders.class)))
                .thenThrow(httpError(HttpStatus.FORBIDDEN));

        assertNull(newService(true).fetchUserinfo(OKTA_USER_ID));
    }

    @Test
    public void fetchUserinfo_returnsNull_onTokenEndpoint404() {
        when(restClientUtil.retrieveGetResponse(contains("/credentials/tokens"), any(HttpHeaders.class)))
                .thenThrow(httpError(HttpStatus.NOT_FOUND));

        assertNull(newService(true).fetchUserinfo(OKTA_USER_ID));
    }

    @Test
    public void fetchUserinfo_returnsNull_onUserinfo401() {
        when(restClientUtil.retrieveGetResponse(contains("/credentials/tokens"), any(HttpHeaders.class)))
                .thenReturn(ResponseEntity.ok(TOKENS_RESPONSE));
        when(restClientUtil.retrieveGetResponse(eq(USERINFO_URI), any(HttpHeaders.class)))
                .thenThrow(httpError(HttpStatus.UNAUTHORIZED));

        assertNull(newService(true).fetchUserinfo(OKTA_USER_ID));
    }

    @Test
    public void fetchUserinfo_returnsNull_whenAccessTokenElementMissing() {
        String idTokenOnly =
                "[{\"id\":\"a\",\"tokenType\":\"urn:okta:params:oauth:token-type:id_token\",\"token\":\"ID_TOKEN\"}]";
        when(restClientUtil.retrieveGetResponse(contains("/credentials/tokens"), any(HttpHeaders.class)))
                .thenReturn(ResponseEntity.ok(idTokenOnly));

        assertNull(newService(true).fetchUserinfo(OKTA_USER_ID));
        verify(restClientUtil, never()).retrieveGetResponse(eq(USERINFO_URI), any(HttpHeaders.class));
    }

    @Test
    public void fetchUserinfo_returnsNull_onMalformedTokensResponse() {
        when(restClientUtil.retrieveGetResponse(contains("/credentials/tokens"), any(HttpHeaders.class)))
                .thenReturn(ResponseEntity.ok("not json at all"));

        assertNull(newService(true).fetchUserinfo(OKTA_USER_ID));
    }

    @Test
    public void fetchUserinfo_returnsNull_whenOktaApiTokenUnavailable() {
        when(oktaApiTokenService.getToken()).thenReturn(null);

        assertNull(newService(true).fetchUserinfo(OKTA_USER_ID));
        verifyNoInteractions(restClientUtil);
    }

    @Test
    public void fetchUserinfo_reMintsAndRetries_onManagementApi401() {
        when(restClientUtil.retrieveGetResponse(contains("/credentials/tokens"), any(HttpHeaders.class)))
                .thenThrow(httpError(HttpStatus.UNAUTHORIZED))
                .thenReturn(ResponseEntity.ok(TOKENS_RESPONSE));
        when(restClientUtil.retrieveGetResponse(eq(USERINFO_URI), any(HttpHeaders.class)))
                .thenReturn(ResponseEntity.ok(USERINFO_BODY));

        JsonNode result = newService(true).fetchUserinfo(OKTA_USER_ID);

        assertEquals("ras-sub", result.get("sub").asText());
        verify(oktaApiTokenService, times(1)).invalidate();
        verify(restClientUtil, times(2)).retrieveGetResponse(contains("/credentials/tokens"), any(HttpHeaders.class));
    }

    @Test
    public void fetchUserinfo_returnsNull_whenRetryAlso401() {
        when(restClientUtil.retrieveGetResponse(contains("/credentials/tokens"), any(HttpHeaders.class)))
                .thenThrow(httpError(HttpStatus.UNAUTHORIZED))
                .thenThrow(httpError(HttpStatus.UNAUTHORIZED));

        assertNull(newService(true).fetchUserinfo(OKTA_USER_ID));
        verify(oktaApiTokenService, times(1)).invalidate();
        verify(restClientUtil, times(2)).retrieveGetResponse(contains("/credentials/tokens"), any(HttpHeaders.class));
    }

    @Test
    public void fetchUserinfo_returnsNull_whenOktaUserIdBlankOrNull() {
        RasUserinfoService svc = newService(true);
        assertNull(svc.fetchUserinfo("  "));
        assertNull(svc.fetchUserinfo(null));
        verifyNoInteractions(restClientUtil);
    }

    @Test
    public void fetchUserinfo_usesDpopScheme_whenTokenDpopBound() {
        when(oktaApiTokenService.getToken())
                .thenReturn(new OktaApiTokenService.OktaApiToken("OKTA_API_TOKEN", true));
        when(dpopProofService.createProof(eq("GET"), contains("/credentials/tokens"), isNull(), eq("OKTA_API_TOKEN")))
                .thenReturn("PROOF1");
        when(restClientUtil.retrieveGetResponse(contains("/credentials/tokens"), any(HttpHeaders.class)))
                .thenReturn(ResponseEntity.ok(TOKENS_RESPONSE));
        when(restClientUtil.retrieveGetResponse(eq(USERINFO_URI), any(HttpHeaders.class)))
                .thenReturn(ResponseEntity.ok(USERINFO_BODY));

        assertEquals("ras-sub", newService(true).fetchUserinfo(OKTA_USER_ID).get("sub").asText());

        ArgumentCaptor<HttpHeaders> headers = ArgumentCaptor.forClass(HttpHeaders.class);
        verify(restClientUtil).retrieveGetResponse(contains("/credentials/tokens"), headers.capture());
        assertEquals("DPoP OKTA_API_TOKEN", headers.getValue().getFirst(HttpHeaders.AUTHORIZATION));
        assertEquals("PROOF1", headers.getValue().getFirst("DPoP"));
    }

    @Test
    public void fetchUserinfo_retriesWithNonce_onManagementApiDpopNonceChallenge() {
        when(oktaApiTokenService.getToken())
                .thenReturn(new OktaApiTokenService.OktaApiToken("OKTA_API_TOKEN", true));
        when(dpopProofService.createProof(eq("GET"), contains("/credentials/tokens"), isNull(), eq("OKTA_API_TOKEN")))
                .thenReturn("P1");
        when(dpopProofService.createProof(eq("GET"), contains("/credentials/tokens"), eq("RNONCE"), eq("OKTA_API_TOKEN")))
                .thenReturn("P2");
        when(restClientUtil.retrieveGetResponse(contains("/credentials/tokens"), any(HttpHeaders.class)))
                .thenThrow(dpopNonce(HttpStatus.UNAUTHORIZED, "RNONCE"))
                .thenReturn(ResponseEntity.ok(TOKENS_RESPONSE));
        when(restClientUtil.retrieveGetResponse(eq(USERINFO_URI), any(HttpHeaders.class)))
                .thenReturn(ResponseEntity.ok(USERINFO_BODY));

        assertEquals("ras-sub", newService(true).fetchUserinfo(OKTA_USER_ID).get("sub").asText());

        verify(oktaApiTokenService, never()).invalidate();
        verify(restClientUtil, times(2)).retrieveGetResponse(contains("/credentials/tokens"), any(HttpHeaders.class));
        verify(dpopProofService).createProof("GET", MGMT_URL + "/api/v1/idps/" + IDP_ID + "/users/" + OKTA_USER_ID + "/credentials/tokens", "RNONCE", "OKTA_API_TOKEN");
    }
}
