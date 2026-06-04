package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

/**
 * Retrieves the RAS userinfo object (which Okta cannot map through token introspection) by:
 *   1. reading the Okta-stored RAS access token from the Okta Management API, then
 *   2. calling the RAS userinfo endpoint directly with that token.
 *
 * This is non-blocking enrichment: {@link #fetchUserinfo(String)} NEVER throws. On any failure
 * (disabled, missing Okta API token, missing stored RAS token, HTTP error, malformed body) it
 * logs a warning and returns {@code null} so login proceeds with the federated data absent.
 *
 * Never logs the Okta API token, the RAS access token, or the raw userinfo body (PII).
 */
@Service
public class RasUserinfoService {

    private static final Logger logger = LoggerFactory.getLogger(RasUserinfoService.class);

    private final boolean fetchEnabled;
    private final String managementApiUrl;
    private final String idpId;
    private final String userinfoUri;
    private final RestClientUtil restClientUtil;
    private final OktaApiTokenService oktaApiTokenService;
    private final DpopProofService dpopProofService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /** Server-supplied DPoP nonce for the Okta Management API; reused across calls, refreshed on challenge. */
    private volatile String resourceNonce;

    @Autowired
    public RasUserinfoService(@Value("${ras.fetch.userinfo.enabled}") boolean fetchEnabled,
                              @Value("${ras.okta.management.api.url}") String managementApiUrl,
                              @Value("${ras.okta.idp.id}") String idpId,
                              @Value("${ras.userinfo.uri}") String userinfoUri,
                              RestClientUtil restClientUtil,
                              OktaApiTokenService oktaApiTokenService,
                              DpopProofService dpopProofService) {
        this.fetchEnabled = fetchEnabled;
        this.managementApiUrl = managementApiUrl;
        this.idpId = idpId;
        this.userinfoUri = userinfoUri;
        this.restClientUtil = restClientUtil;
        this.oktaApiTokenService = oktaApiTokenService;
        this.dpopProofService = dpopProofService;
    }

    /**
     * @param oktaUserId the Okta-internal user id (the introspection "uid" claim)
     * @return the parsed RAS userinfo node, or {@code null} on any failure. Never throws.
     */
    public JsonNode fetchUserinfo(String oktaUserId) {
        if (!fetchEnabled) {
            logger.info("RAS userinfo fetch is disabled (ras.fetch.userinfo.enabled=false)");
            return null;
        }
        if (oktaUserId == null || oktaUserId.isBlank()) {
            logger.warn("RAS userinfo fetch skipped: missing Okta user id");
            return null;
        }
        try {
            String rasAccessToken = retrieveStoredRasToken(oktaUserId);
            if (rasAccessToken == null) {
                logger.warn("RAS userinfo fetch skipped: no stored RAS access token for Okta user");
                return null;
            }
            return callUserinfo(rasAccessToken);
        } catch (Exception ex) {
            // Log the exception type only: a JSON-parse exception message embeds a snippet of the
            // unparseable body, which here can contain the RAS access token or userinfo PII.
            logger.warn("RAS userinfo fetch failed: {}", ex.getClass().getSimpleName());
            return null;
        }
    }

    /**
     * GET the Okta-stored credential tokens and return the RAS access token value, or null.
     * Handles two distinct 401-class failures, each retried at most once:
     *   - a DPoP resource nonce challenge ({@code dpop-nonce} header) -> set nonce, retry (token unchanged);
     *   - an expired/invalid Okta API token (401, no nonce) -> invalidate, re-mint, retry.
     */
    private String retrieveStoredRasToken(String oktaUserId) throws JsonProcessingException {
        String url = this.managementApiUrl + "/api/v1/idps/" + this.idpId
                + "/users/" + oktaUserId + "/credentials/tokens";
        OktaApiTokenService.OktaApiToken token = this.oktaApiTokenService.getToken();
        if (token == null || token.value() == null) {
            throw new IllegalStateException("could not obtain Okta API token");
        }
        ResponseEntity<String> resp;
        try {
            resp = getManagementApi(url, token);
        } catch (HttpClientErrorException ex) {
            String nonce = nonceFrom(ex);
            if (nonce != null) {
                logger.info("Okta Management API requires a DPoP nonce; retrying once");
                this.resourceNonce = nonce;
                resp = getManagementApi(url, token); // a second failure propagates to fetchUserinfo's catch
            } else if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                logger.info("Okta Management API returned 401; re-minting Okta API token and retrying once");
                this.oktaApiTokenService.invalidate();
                token = this.oktaApiTokenService.getToken();
                if (token == null || token.value() == null) {
                    throw new IllegalStateException("could not obtain Okta API token");
                }
                resp = getManagementApi(url, token); // a second failure propagates to fetchUserinfo's catch
            } else {
                logger.warn("Okta Management API token lookup failed: {}", ex.getStatusCode());
                return null;
            }
        }
        return extractAccessToken(resp.getBody());
    }

    /**
     * Issue the Management API GET using the scheme the token was bound as: DPoP (Authorization: DPoP +
     * a fresh proof carrying ath and the current resource nonce) or plain Bearer.
     */
    private ResponseEntity<String> getManagementApi(String url, OktaApiTokenService.OktaApiToken token) {
        HttpHeaders headers = new HttpHeaders();
        if (token.dpopBound()) {
            headers.set(HttpHeaders.AUTHORIZATION, "DPoP " + token.value());
            headers.set("DPoP", this.dpopProofService.createProof("GET", url, this.resourceNonce, token.value()));
        } else {
            headers.setBearerAuth(token.value());
        }
        return this.restClientUtil.retrieveGetResponse(url, headers);
    }

    /** @return the {@code dpop-nonce} response header value if present and non-blank, else null. */
    private String nonceFrom(HttpClientErrorException ex) {
        HttpHeaders responseHeaders = ex.getResponseHeaders();
        String nonce = (responseHeaders == null) ? null : responseHeaders.getFirst("dpop-nonce");
        return (nonce != null && !nonce.isBlank()) ? nonce : null;
    }

    /** Select the element whose tokenType ends with "access_token" and return its "token" value. */
    private String extractAccessToken(String body) throws JsonProcessingException {
        if (body == null) {
            logger.warn("Okta Management API token response had a null body");
            return null;
        }
        JsonNode tokens = objectMapper.readTree(body);
        if (tokens == null || !tokens.isArray()) {
            logger.warn("Okta Management API token response was not a JSON array");
            return null;
        }
        for (JsonNode token : tokens) {
            JsonNode tokenType = token.get("tokenType");
            if (tokenType != null && tokenType.asText("").endsWith("access_token")) {
                JsonNode value = token.get("token");
                if (value != null && !value.isNull() && !value.asText().isBlank()) {
                    return value.asText();
                }
            }
        }
        logger.warn("No access_token element found in Okta Management API token response");
        return null;
    }

    private JsonNode callUserinfo(String rasAccessToken) throws JsonProcessingException {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(rasAccessToken);
        ResponseEntity<String> resp = this.restClientUtil.retrieveGetResponse(this.userinfoUri, headers);
        String body = resp.getBody();
        if (body == null) {
            logger.warn("RAS userinfo response had a null body");
            return null;
        }
        return objectMapper.readTree(body);
    }
}
