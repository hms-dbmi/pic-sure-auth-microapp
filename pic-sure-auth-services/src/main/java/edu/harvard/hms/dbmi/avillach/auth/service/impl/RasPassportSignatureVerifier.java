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
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Cryptographically verifies the RS256 signature of RAS passport / GA4GH visa JWTs against the
 * public keys RAS publishes at its JWKS endpoint.
 *
 * <p>Because Okta brokers the RAS connection, PIC-SURE never talks to RAS directly. Signature
 * verification against RAS's JWKS is therefore the only thing that guarantees the dbGaP permissions
 * carried in a passport were issued by RAS and were not tampered with in the Okta hop. The keys are
 * discovered via standard OIDC metadata ({@code <issuer>/.well-known/openid-configuration} ->
 * {@code jwks_uri}) and cached by {@code kid}; an unknown {@code kid} triggers a refresh to pick up
 * RAS key rotation.</p>
 *
 * <p>The discovery and JWKS documents are fetched with the JDK {@link HttpClient} negotiating
 * HTTP/2. The shared Apache HttpClient5 {@code RestTemplate} is HTTP/1.1-only, and the NIH gateway
 * truncates responses on that path (the body is cut short mid-stream), which made every passport
 * fail signature verification. The JDK client behaves like {@code curl} and reads the full body.</p>
 */
@Service
public class RasPassportSignatureVerifier {

    private final Logger logger = LoggerFactory.getLogger(RasPassportSignatureVerifier.class);

    private final String issuer;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, PublicKey> keyCache = new ConcurrentHashMap<>();
    private final UrlFetcher urlFetcher;

    @Autowired
    public RasPassportSignatureVerifier(@Value("${ras.passport.issuer}") String rasPassportIssuer,
                                        @Value("${http.proxyHost:}") String proxyHost,
                                        @Value("${http.proxyPort:8080}") int proxyPort) {
        this(rasPassportIssuer, defaultFetcher(proxyHost, proxyPort));
    }

    /** Package-private constructor allowing tests to supply a canned fetcher (no real HTTP). */
    RasPassportSignatureVerifier(String rasPassportIssuer, UrlFetcher urlFetcher) {
        this.issuer = rasPassportIssuer == null ? null : rasPassportIssuer.replaceAll("/$", "");
        this.urlFetcher = urlFetcher;
        logger.info("RasPassportSignatureVerifier initialized with issuer: {}", this.issuer);
    }

    /**
     * @param jwt an encoded RAS passport or GA4GH visa JWT (header.payload.signature)
     * @return true only if the signature verifies against RAS's published JWKS key for the token's
     * {@code kid}. Returns false for a missing/blank token, an unknown {@code kid}, a malformed token,
     * an expired token, or any signature mismatch. Fails closed: any error means "not valid".
     */
    public boolean isSignatureValid(String jwt) {
        if (StringUtils.isBlank(jwt)) {
            logger.error("isSignatureValid() rejecting blank passport token");
            return false;
        }

        try {
            String kid = extractKid(jwt);
            PublicKey key = resolveKey(kid);
            if (key == null) {
                logger.error("isSignatureValid() rejecting passport - no RAS JWKS key found for kid {}", kid);
                return false;
            }

            Jwts.parser().verifyWith(key).build().parseSignedClaims(jwt);
            return true;
        } catch (Exception e) {
            logger.error("isSignatureValid() rejecting passport - {}: {}", e.getClass().getSimpleName(), e.getMessage());
            return false;
        }
    }

    private String extractKid(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("token is not a JWS (expected 3 segments)");
        }
        JsonNode header = objectMapper.readTree(Base64.getUrlDecoder().decode(parts[0]));
        JsonNode kid = header.get("kid");
        return kid == null ? null : kid.asText();
    }

    private PublicKey resolveKey(String kid) {
        if (kid == null) {
            return null;
        }
        PublicKey cached = keyCache.get(kid);
        if (cached != null) {
            return cached;
        }
        // Unknown kid: refresh once to pick up rotated RAS keys, then look again.
        refreshKeys();
        return keyCache.get(kid);
    }

    private synchronized void refreshKeys() {
        String jwksUri = null;
        try {
            jwksUri = discoverJwksUri();
            String body = fetchBody("JWKS", jwksUri);
            JsonNode keys = objectMapper.readTree(body).get("keys");
            if (keys == null) {
                logger.error("refreshKeys() RAS JWKS response had no 'keys' array");
                return;
            }

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
                BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
                BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));
                PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
                keyCache.put(kid, key);
            }
        } catch (Exception ex) {
            logger.error("refreshKeys() failed to load RAS JWKS from {} - {}: {}",
                    jwksUri, ex.getClass().getSimpleName(), ex.getMessage());
        }
    }

    private String discoverJwksUri() throws Exception {
        String discoveryUrl = issuer + "/.well-known/openid-configuration";
        String body = fetchBody("OIDC discovery", discoveryUrl);
        JsonNode config = objectMapper.readTree(body);
        JsonNode jwksUri = config.get("jwks_uri");
        if (jwksUri == null) {
            throw new IllegalStateException("RAS OIDC discovery document has no jwks_uri at " + discoveryUrl);
        }
        return jwksUri.asText();
    }

    /**
     * Fetches a URL and logs what we actually received at INFO (no DEBUG required) so transport
     * problems (truncation, wrong Content-Length, HTTP version) are diagnosable. The discovery/JWKS
     * documents are public (no secrets), so logging the body is safe; capped at 2048 chars.
     */
    private String fetchBody(String what, String url) throws Exception {
        FetchResult result = urlFetcher.fetch(url);
        String body = result.body();
        logger.info("RAS {} fetch: url={} status={} httpVersion={} contentLength={} bodyLength={} body={}",
                what, url, result.status(), result.httpVersion(), result.contentLengthHeader(),
                body == null ? "null" : body.length(),
                body == null ? "null" : body.substring(0, Math.min(2048, body.length())));
        return body;
    }

    private static UrlFetcher defaultFetcher(String proxyHost, int proxyPort) {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(10));
        if (StringUtils.isNotBlank(proxyHost)) {
            builder.proxy(ProxySelector.of(new InetSocketAddress(proxyHost, proxyPort)));
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
        return value == null ? null : value.asText();
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
