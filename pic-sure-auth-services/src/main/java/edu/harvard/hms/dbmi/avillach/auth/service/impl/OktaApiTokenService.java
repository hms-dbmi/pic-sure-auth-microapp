package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Mints and caches a short-lived Okta API access token using OAuth-for-Okta client-credentials
 * with private_key_jwt client authentication. The token is used as a Bearer credential against
 * the Okta Management API. The cache is thread-safe and re-mints shortly before expiry, on
 * expiry, or after {@link #invalidate()} (called by callers on a 401 from the Management API).
 *
 * Never logs the private key, the client assertion, or the minted token.
 */
@Service
public class OktaApiTokenService {

    private static final Logger logger = LoggerFactory.getLogger(OktaApiTokenService.class);

    /** Re-mint this many millis before the token actually expires. */
    private static final long EXPIRY_SKEW_MILLIS = 60_000L;
    /** client_assertion lifetime (short-lived). */
    private static final long ASSERTION_TTL_MILLIS = 300_000L;
    private static final String CLIENT_ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private final String managementApiUrl;
    private final String apiClientId;
    private final String apiScope;
    private final RestClientUtil restClientUtil;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final PrivateKey signingKey; // null if not configured / unparseable

    /** Immutable (token, expiry) pair held in one volatile reference so reads are atomic and consistent. */
    private volatile CachedToken cache;

    private record CachedToken(String token, long expiresAtMillis) {}

    @Autowired
    public OktaApiTokenService(@Value("${ras.okta.management.api.url}") String managementApiUrl,
                               @Value("${ras.okta.api.client.id}") String apiClientId,
                               @Value("${ras.okta.api.private.key}") String apiPrivateKey,
                               @Value("${ras.okta.api.scope}") String apiScope,
                               RestClientUtil restClientUtil) {
        this.managementApiUrl = managementApiUrl;
        this.apiClientId = apiClientId;
        this.apiScope = apiScope;
        this.restClientUtil = restClientUtil;
        this.signingKey = parsePrivateKey(apiPrivateKey);
    }

    /**
     * @return a valid cached Okta API access token, minting a fresh one if the cache is empty or
     *         within the expiry-skew window; {@code null} if a token could not be obtained.
     */
    public String getAccessToken() {
        CachedToken current = this.cache;       // lock-free fast path for the common cache hit
        if (isValid(current)) {
            return current.token();
        }
        synchronized (this) {
            current = this.cache;                // re-check under lock; another thread may have minted
            if (isValid(current)) {
                return current.token();
            }
            return mintToken();
        }
    }

    private boolean isValid(CachedToken c) {
        return c != null && System.currentTimeMillis() < (c.expiresAtMillis() - EXPIRY_SKEW_MILLIS);
    }

    /** Drop any cached token so the next {@link #getAccessToken()} re-mints. Call after a 401. */
    public synchronized void invalidate() {
        this.cache = null;
    }

    private String mintToken() {
        if (signingKey == null) {
            logger.warn("OktaApiTokenService cannot mint a token: signing key is not configured");
            return null;
        }
        String tokenUrl = this.managementApiUrl + "/oauth2/v1/token";
        try {
            String assertion = buildClientAssertion(tokenUrl);
            String body = "grant_type=client_credentials"
                    + "&scope=" + URLEncoder.encode(this.apiScope, StandardCharsets.UTF_8)
                    + "&client_assertion_type=" + URLEncoder.encode(CLIENT_ASSERTION_TYPE, StandardCharsets.UTF_8)
                    + "&client_assertion=" + URLEncoder.encode(assertion, StandardCharsets.UTF_8);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));

            ResponseEntity<String> resp = this.restClientUtil.retrievePostResponse(tokenUrl, headers, body);
            String rawBody = resp.getBody();
            if (rawBody == null) {
                logger.warn("Okta API token response had a null body");
                return null;
            }
            JsonNode json = objectMapper.readTree(rawBody);
            JsonNode accessToken = json.get("access_token");
            if (accessToken == null || accessToken.isNull()) {
                logger.warn("Okta API token response did not contain an access_token");
                return null;
            }
            long expiresInSec = json.has("expires_in") ? json.get("expires_in").asLong() : 0L;
            String token = accessToken.asText();
            this.cache = new CachedToken(token, System.currentTimeMillis() + (expiresInSec * 1000L));
            logger.info("Minted new Okta API access token (expires in {}s)", expiresInSec);
            return token;
        } catch (Exception ex) {
            // Log the exception type only: a JSON-parse exception message embeds a snippet of the
            // response body, which on the token endpoint can contain access-token material.
            logger.warn("Failed to mint Okta API access token: {}", ex.getClass().getSimpleName());
            this.cache = null;
            return null;
        }
    }

    private String buildClientAssertion(String audience) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .issuer(this.apiClientId)
                .subject(this.apiClientId)
                .audience().add(audience).and()
                .issuedAt(new Date(now))
                .expiration(new Date(now + ASSERTION_TTL_MILLIS))
                .id(UUID.randomUUID().toString())
                .signWith(this.signingKey, Jwts.SIG.RS256)
                .compact();
    }

    private PrivateKey parsePrivateKey(String key) {
        // Spring injects the literal "false" for unset ras.* properties (see application.properties defaults).
        if (key == null || key.isBlank() || "false".equalsIgnoreCase(key)) {
            logger.warn("ras.okta.api.private.key is not configured; Okta API token minting disabled");
            return null;
        }
        try {
            String normalized = key
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(normalized);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception ex) {
            // Never log key material.
            logger.warn("Failed to parse ras.okta.api.private.key: {}", ex.getClass().getSimpleName());
            return null;
        }
    }
}
