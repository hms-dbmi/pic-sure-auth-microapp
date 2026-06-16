package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.LongSupplier;

/**
 * Cryptographically verifies the RS256 signature of RAS passport / GA4GH visa JWTs against the
 * public keys RAS publishes at its JWKS endpoint.
 *
 * <p>Because Okta brokers the RAS connection, PIC-SURE never talks to RAS directly. Signature
 * verification against RAS's JWKS is therefore the only thing that guarantees the dbGaP permissions
 * carried in a passport were issued by RAS and were not tampered with in the Okta hop. Keys are
 * discovered via standard OIDC metadata ({@code <issuer>/.well-known/openid-configuration} ->
 * {@code jwks_uri}) and cached by {@code kid}.</p>
 *
 * <p>Cache discipline:
 * <ul>
 *   <li>The discovered {@code jwks_uri} is cached so a key refresh is a single round trip, not two.</li>
 *   <li>An unknown {@code kid} triggers at most one refresh per {@link #REFRESH_THROTTLE_MS} window,
 *       so a flood of tokens bearing keys RAS never published cannot turn into a JWKS refetch storm.</li>
 *   <li>The whole key set is re-pulled at least every {@link #CACHE_TTL_MS} so a key RAS rotates out
 *       (or revokes while reusing its {@code kid}) stops being trusted.</li>
 * </ul>
 * The HTTP fetch uses the JDK {@link HttpClient} negotiating HTTP/2, because the shared Apache
 * HttpClient5 {@code RestTemplate} is HTTP/1.1-only and the NIH gateway truncates responses on that
 * path.</p>
 */
@Service
public class RasPassportSignatureVerifier {

    private static final String RS256 = "RS256";
    /** Do not refetch the JWKS more than once per this window, even on repeated unknown-kid misses. */
    static final long REFRESH_THROTTLE_MS = 60_000L;
    /** Re-pull the JWKS at least this often so rotated-out / revoked keys stop being trusted. */
    static final long CACHE_TTL_MS = 3_600_000L;

    private final Logger logger = LoggerFactory.getLogger(RasPassportSignatureVerifier.class);

    private final String issuer;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final UrlFetcher urlFetcher;
    private final LongSupplier clock;

    private volatile Map<String, PublicKey> keyCache = Map.of();
    private volatile String cachedJwksUri;
    private volatile long lastRefreshAttemptMs;
    private volatile long lastSuccessfulRefreshMs;

    @Autowired
    public RasPassportSignatureVerifier(@Value("${ras.passport.issuer}") String rasPassportIssuer,
                                        @Value("${http.proxyHost:}") String proxyHost,
                                        @Value("${http.proxyPort:8080}") int proxyPort) {
        this(rasPassportIssuer, defaultFetcher(proxyHost, proxyPort));
    }

    /** Package-private constructor allowing tests to supply a canned fetcher (no real HTTP). */
    RasPassportSignatureVerifier(String rasPassportIssuer, UrlFetcher urlFetcher) {
        this(rasPassportIssuer, urlFetcher, System::currentTimeMillis);
    }

    /** Package-private constructor allowing tests to control time (for throttle / TTL behavior). */
    RasPassportSignatureVerifier(String rasPassportIssuer, UrlFetcher urlFetcher, LongSupplier clock) {
        this.issuer = rasPassportIssuer == null ? null : rasPassportIssuer.replaceAll("/$", "");
        this.urlFetcher = urlFetcher;
        this.clock = clock;
        if (StringUtils.isBlank(this.issuer) || "false".equalsIgnoreCase(this.issuer)) {
            logger.warn("RasPassportSignatureVerifier: ras.passport.issuer is not configured (value='{}'); "
                    + "RAS passport signature verification WILL FAIL until it is set to the RAS STS issuer.", this.issuer);
        } else {
            logger.info("RasPassportSignatureVerifier initialized with issuer: {}", this.issuer);
        }
    }

    /**
     * @param jwt an encoded RAS passport or GA4GH visa JWT (header.payload.signature)
     * @return true only if the token is RS256-signed and its signature verifies against RAS's published
     * JWKS key for the token's {@code kid}. Returns false for a missing/blank token, a non-RS256 alg,
     * an unknown {@code kid}, a malformed token, an expired token, or any signature mismatch. Fails
     * closed: any error means "not valid".
     */
    public boolean isSignatureValid(String jwt) {
        if (StringUtils.isBlank(jwt)) {
            logger.error("isSignatureValid() rejecting blank passport token");
            return false;
        }

        try {
            JsonNode header = parseHeader(jwt);
            String alg = text(header, "alg");
            if (!RS256.equals(alg)) {
                logger.error("isSignatureValid() rejecting passport - unexpected JWS alg {} (only RS256 is accepted)", alg);
                return false;
            }
            PublicKey key = resolveKey(text(header, "kid"));
            if (key == null) {
                logger.error("isSignatureValid() rejecting passport - no RAS JWKS key found for kid {}", text(header, "kid"));
                return false;
            }

            Jwts.parser().verifyWith(key).build().parseSignedClaims(jwt);
            return true;
        } catch (Exception e) {
            logger.error("isSignatureValid() rejecting passport - {}: {}", e.getClass().getSimpleName(), e.getMessage());
            return false;
        }
    }

    private JsonNode parseHeader(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("token is not a JWS (expected 3 segments)");
        }
        return objectMapper.readTree(Base64.getUrlDecoder().decode(parts[0]));
    }

    private PublicKey resolveKey(String kid) {
        if (kid == null) {
            return null;
        }
        long now = clock.getAsLong();
        PublicKey cached = keyCache.get(kid);
        boolean stale = (now - lastSuccessfulRefreshMs) > CACHE_TTL_MS;
        if (cached != null && !stale) {
            return cached;
        }
        maybeRefreshKeys(now);
        return keyCache.get(kid);
    }

    private synchronized void maybeRefreshKeys(long now) {
        // Throttle: a kid that is simply absent (rotated/forged/stale) must not refetch on every call.
        if (now - lastRefreshAttemptMs < REFRESH_THROTTLE_MS && lastRefreshAttemptMs != 0L) {
            return;
        }
        lastRefreshAttemptMs = now;
        try {
            String jwksUri = cachedJwksUri;
            if (jwksUri == null) {
                jwksUri = discoverJwksUri();
                cachedJwksUri = jwksUri;
            }

            JsonNode keys = fetchJson("JWKS", jwksUri).get("keys");
            if (keys == null) {
                logger.error("maybeRefreshKeys() RAS JWKS response had no 'keys' array");
                return;
            }

            Map<String, PublicKey> fresh = new HashMap<>();
            for (JsonNode jwk : keys) {
                if (!"RSA".equals(text(jwk, "kty"))) {
                    continue;
                }
                String kid = text(jwk, "kid");
                String n = text(jwk, "n");
                String e = text(jwk, "e");
                if (kid == null || n == null || e == null) {
                    continue;
                }
                fresh.put(kid, toRsaPublicKey(n, e));
            }

            if (!fresh.isEmpty()) {
                // Replace (not merge) so keys RAS no longer publishes are dropped.
                keyCache = Map.copyOf(fresh);
                lastSuccessfulRefreshMs = now;
            }
        } catch (Exception ex) {
            // Re-discover next time in case jwks_uri itself changed. Keep the existing cache so a
            // transient JWKS outage does not reject users whose key we already hold.
            cachedJwksUri = null;
            logger.error("maybeRefreshKeys() failed to load RAS JWKS - {}: {}", ex.getClass().getSimpleName(), ex.getMessage());
        }
    }

    private String discoverJwksUri() throws Exception {
        String discoveryUrl = issuer + "/.well-known/openid-configuration";
        JsonNode config = fetchJson("OIDC discovery", discoveryUrl);
        JsonNode jwksUri = config.get("jwks_uri");
        if (jwksUri == null) {
            throw new IllegalStateException("RAS OIDC discovery document has no jwks_uri at " + discoveryUrl);
        }
        return jwksUri.asText();
    }

    private static PublicKey toRsaPublicKey(String n, String e) throws Exception {
        BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
        BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
    }

    /**
     * Fetches a URL and parses it as JSON. Logs status / HTTP version / Content-Length / body length
     * at INFO on every fetch so a transport problem (a truncated body, a wrong Content-Length, an
     * unexpected HTTP version) is visible without enabling DEBUG. A non-2xx status is rejected, and
     * only when the body fails to parse do we log the body itself (capped at 2048 chars).
     */
    private JsonNode fetchJson(String what, String url) throws Exception {
        FetchResult result = urlFetcher.fetch(url);
        String body = result.body();
        logger.info("RAS {} fetch: url={} status={} httpVersion={} contentLength={} bodyLength={}",
                what, url, result.status(), result.httpVersion(), result.contentLengthHeader(),
                body == null ? "null" : body.length());
        if (result.status() < 200 || result.status() >= 300) {
            throw new IllegalStateException("RAS " + what + " fetch returned HTTP status " + result.status());
        }
        try {
            return objectMapper.readTree(body);
        } catch (Exception e) {
            logger.error("RAS {} fetch from {} returned an unparseable body (status={} contentLength={} bodyLength={}) - "
                            + "likely truncated or non-JSON. Body: {}",
                    what, url, result.status(), result.contentLengthHeader(),
                    body == null ? "null" : body.length(),
                    body == null ? "null" : body.substring(0, Math.min(2048, body.length())));
            throw e;
        }
    }

    private static UrlFetcher defaultFetcher(String proxyHost, int proxyPort) {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(10));
        if (StringUtils.isNotBlank(proxyHost)) {
            builder.proxy(java.net.ProxySelector.of(new InetSocketAddress(proxyHost, proxyPort)));
        }
        HttpClient client = builder.build();

        return url -> {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(15))
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return new FetchResult(
                    response.statusCode(),
                    String.valueOf(response.version()),
                    response.headers().firstValue("content-length").orElse(null),
                    response.body());
        };
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return (value == null || value.isNull()) ? null : value.asText();
    }

    /** Seam for fetching a URL's body, so tests can supply canned responses without real HTTP. */
    @FunctionalInterface
    interface UrlFetcher {
        FetchResult fetch(String url) throws Exception;
    }

    /** Minimal HTTP response shape needed for verification and diagnostics. */
    record FetchResult(int status, String httpVersion, String contentLengthHeader, String body) {
    }
}
