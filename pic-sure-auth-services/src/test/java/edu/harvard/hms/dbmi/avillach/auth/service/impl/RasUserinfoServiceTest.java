package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class RasUserinfoServiceTest {

    private RestClientUtil restClientUtil;
    private OktaApiTokenService oktaApiTokenService;

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
        when(oktaApiTokenService.getAccessToken()).thenReturn("OKTA_API_TOKEN");
    }

    private RasUserinfoService newService(boolean enabled) {
        return new RasUserinfoService(enabled, MGMT_URL, IDP_ID, USERINFO_URI, restClientUtil, oktaApiTokenService);
    }

    private HttpClientErrorException httpError(HttpStatus status) {
        return HttpClientErrorException.create(status, status.getReasonPhrase(), HttpHeaders.EMPTY, null, null);
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
        when(oktaApiTokenService.getAccessToken()).thenReturn(null);

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
}
