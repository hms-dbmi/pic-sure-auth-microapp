package edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasOidcTokens;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import io.jsonwebtoken.Claims;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

/**
 * Direct OIDC client for NIH RAS (Researcher Auth Service). Replaces the Okta-brokered
 * token exchange/introspection: PSAMA now exchanges the authorization code at RAS itself,
 * validates the RS256 ID token against the RAS JWKS, and calls the v1.1 userinfo endpoint
 * with the RAS access token.
 *
 * Endpoints are resolved from {@code /.well-known/openid-configuration} (loaded lazily,
 * cached for the process lifetime) with fallbacks to the paths documented in the NIH RAS
 * Partner Developer Guide v1.5 §4. The userinfo endpoint deliberately does NOT come from
 * discovery: discovery advertises v1, which omits the GA4GH passport claims.
 *
 * Never logs tokens, codes, or secrets.
 */
@Service
public class RasOidcClient {

    /** Same scope set the Okta-brokered integration requested from RAS. */
    static final String SCOPES = "openid profile email ga4gh_passport_v1 researcher_role"
            + " federated_identities_ial2 federated_identities federated_sources";

    private static final String DISCOVERY_PATH = "/.well-known/openid-configuration";
    private static final String FALLBACK_AUTHORIZE_PATH = "/auth/oauth/v2/authorize";
    private static final String FALLBACK_TOKEN_PATH = "/auth/oauth/v2/token";
    private static final String FALLBACK_JWKS_PATH = "/openid/connect/jwks.json";
    private static final String USERINFO_V11_PATH = "/openid/connect/v1.1/userinfo";

    private final Logger logger = LoggerFactory.getLogger(RasOidcClient.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final RestClientUtil restClientUtil;
    private final OidcIdTokenValidator idTokenValidator;
    private final OidcFlowStateStore stateStore;
    private final String baseUri;
    private final String clientId;
    private final String clientSecret;
    private final String userinfoUriOverride;
    private final String issuer;

    private volatile JsonNode discovery;

    public RasOidcClient(RestClientUtil restClientUtil,
                         OidcIdTokenValidator idTokenValidator,
                         OidcFlowStateStore stateStore,
                         @Value("${ras.idp.uri}") String baseUri,
                         @Value("${ras.client.id}") String clientId,
                         @Value("${ras.client.secret}") String clientSecret,
                         @Value("${ras.userinfo.uri:}") String userinfoUriOverride,
                         @Value("${ras.passport.issuer}") String issuer) {
        this.restClientUtil = restClientUtil;
        this.idTokenValidator = idTokenValidator;
        this.stateStore = stateStore;
        this.baseUri = baseUri.replaceAll("/$", "");
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.userinfoUriOverride = userinfoUriOverride;
        this.issuer = issuer;
    }

    /**
     * Builds the RAS authorization redirect for a new login attempt, generating and storing
     * the flow's state (CSRF), nonce (ID-token binding), and PKCE verifier (when RAS
     * advertises S256 support in discovery).
     */
    public String buildAuthorizeUrl(String host) {
        String nonce = OidcFlowStateStore.randomToken();
        String codeVerifier = pkceSupported() ? OidcFlowStateStore.randomToken() : null;
        String state = stateStore.storeNewFlow(nonce, codeVerifier);

        StringBuilder url = new StringBuilder(authorizeEndpoint())
                .append("?response_type=code")
                .append("&client_id=").append(urlEncode(clientId))
                .append("&redirect_uri=").append(urlEncode(redirectUri(host)))
                .append("&scope=").append(urlEncode(SCOPES))
                .append("&state=").append(urlEncode(state))
                .append("&nonce=").append(urlEncode(nonce));
        if (codeVerifier != null) {
            url.append("&code_challenge=").append(urlEncode(s256(codeVerifier)))
               .append("&code_challenge_method=S256");
        }
        return url.toString();
    }

    /**
     * Exchanges the authorization code at the RAS token endpoint (form-encoded POST,
     * client_secret_basic). Returns null on any failure; never throws.
     */
    public RasOidcTokens exchangeCode(String code, String host, String codeVerifier) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBasicAuth(clientId, clientSecret);
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            StringBuilder body = new StringBuilder("grant_type=authorization_code")
                    .append("&scope=openid")
                    .append("&code=").append(urlEncode(code))
                    .append("&redirect_uri=").append(urlEncode(redirectUri(host)));
            if (codeVerifier != null) {
                body.append("&code_verifier=").append(urlEncode(codeVerifier));
            }

            ResponseEntity<String> resp = restClientUtil.retrievePostResponse(tokenEndpoint(), headers, body.toString());
            JsonNode json = objectMapper.readTree(Objects.requireNonNull(resp.getBody()));
            String accessToken = json.path("access_token").asText(null);
            String idToken = json.path("id_token").asText(null);
            if (accessToken == null || idToken == null) {
                logger.error("RAS token response missing access_token or id_token");
                return null;
            }
            return new RasOidcTokens(accessToken, idToken, json.path("refresh_token").asText(null));
        } catch (Exception e) {
            logger.error("RAS code-for-token exchange failed: {}", e.getClass().getSimpleName());
            return null;
        }
    }

    /** Full ID-token validation (RS256/JWKS, iss, aud, exp with skew) plus the flow-nonce check. */
    public Optional<Claims> validateIdToken(String idToken, String expectedNonce) {
        Optional<Claims> claims = idTokenValidator.validate(idToken, jwksUri(), issuer, clientId);
        if (claims.isEmpty()) {
            return Optional.empty();
        }
        String nonce = claims.get().get("nonce", String.class);
        if (expectedNonce == null || !expectedNonce.equals(nonce)) {
            logger.error("ID token nonce does not match the stored flow nonce");
            return Optional.empty();
        }
        return claims;
    }

    /**
     * Calls RAS v1.1 userinfo with the access token. Handles both plain-JSON and signed-JWT
     * ({@code application/jwt}) responses; JWT responses are validated against the same JWKS.
     * Returns null on any failure; never throws or logs response bodies (PII).
     */
    public JsonNode fetchUserinfo(String accessToken) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            ResponseEntity<String> resp = restClientUtil.retrieveGetResponse(userinfoEndpoint(), headers);
            String body = resp.getBody();
            if (body == null) {
                logger.error("RAS userinfo response had a null body");
                return null;
            }
            MediaType contentType = resp.getHeaders().getContentType();
            if (contentType != null && "jwt".equalsIgnoreCase(contentType.getSubtype())) {
                Optional<Claims> claims = idTokenValidator.validate(body.trim(), jwksUri(), issuer, clientId);
                if (claims.isEmpty()) {
                    logger.error("Signed userinfo JWT failed validation");
                    return null;
                }
                return objectMapper.valueToTree(claims.get());
            }
            return objectMapper.readTree(body);
        } catch (Exception e) {
            // Exception type only: parse errors can embed token/PII body snippets.
            logger.error("RAS userinfo call failed: {}", e.getClass().getSimpleName());
            return null;
        }
    }

    /**
     * Merges the userinfo document with the validated ID-token claims into the single claims
     * object the downstream pipeline consumes (shaped like the old Okta introspection response).
     * The ID token is authoritative for sub/acr/txn/iss.
     */
    public ObjectNode mergeClaims(JsonNode userinfo, Claims idTokenClaims) {
        ObjectNode merged = userinfo.deepCopy();
        merged.put("sub", idTokenClaims.getSubject());
        putIfPresent(merged, "acr", idTokenClaims.get("acr", String.class));
        putIfPresent(merged, "txn", idTokenClaims.get("txn", String.class));
        putIfPresent(merged, "iss", idTokenClaims.getIssuer());
        return merged;
    }

    /** Must byte-for-byte match the redirect_uri registered with RAS for this environment. */
    public String redirectUri(String host) {
        return "https://" + host + "/login/loading";
    }

    String authorizeEndpoint() {
        return endpointFromDiscovery("authorization_endpoint", FALLBACK_AUTHORIZE_PATH);
    }

    String tokenEndpoint() {
        return endpointFromDiscovery("token_endpoint", FALLBACK_TOKEN_PATH);
    }

    String jwksUri() {
        return endpointFromDiscovery("jwks_uri", FALLBACK_JWKS_PATH);
    }

    String userinfoEndpoint() {
        if (StringUtils.isNotBlank(userinfoUriOverride)) {
            return userinfoUriOverride;
        }
        return baseUri + USERINFO_V11_PATH;
    }

    boolean pkceSupported() {
        for (JsonNode method : discovery().path("code_challenge_methods_supported")) {
            if ("S256".equals(method.asText())) {
                return true;
            }
        }
        return false;
    }

    private String endpointFromDiscovery(String field, String fallbackPath) {
        String value = discovery().path(field).asText(null);
        return value != null ? value : baseUri + fallbackPath;
    }

    private JsonNode discovery() {
        JsonNode current = discovery;
        if (current != null) {
            return current;
        }
        synchronized (this) {
            if (discovery == null) {
                try {
                    ResponseEntity<String> resp =
                            restClientUtil.retrieveGetResponse(baseUri + DISCOVERY_PATH, new HttpHeaders());
                    discovery = objectMapper.readTree(Objects.requireNonNull(resp.getBody()));
                    logger.info("Loaded RAS OIDC discovery metadata from {}", baseUri + DISCOVERY_PATH);
                } catch (Exception e) {
                    // Cached for the process lifetime: the fallbacks are the guide-documented paths.
                    logger.warn("Could not load RAS OIDC discovery metadata, using documented endpoint paths: {}",
                            e.getClass().getSimpleName());
                    discovery = objectMapper.createObjectNode();
                }
            }
            return discovery;
        }
    }

    private static void putIfPresent(ObjectNode node, String field, String value) {
        if (value != null) {
            node.put(field, value);
        }
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String s256(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
