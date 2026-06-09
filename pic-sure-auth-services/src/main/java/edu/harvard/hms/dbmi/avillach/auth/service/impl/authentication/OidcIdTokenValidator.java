package edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.ProtectedHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Validates RS256-signed JWTs (ID tokens, signed userinfo responses) against an OIDC JWKS
 * endpoint. JWKS documents are cached per URI; an unseen {@code kid} triggers at most one
 * refresh per {@link #refreshMinIntervalMs} window to pick up rotated keys. The {@code exp}
 * claim is REQUIRED — tokens without {@code exp} are rejected. Clock-skew leeway of
 * {@value #CLOCK_SKEW_SECONDS} seconds applies to {@code exp} and {@code nbf} checks only
 * (jjwt does not validate {@code iat}).
 */
@Service
public class OidcIdTokenValidator {

    private static final long CLOCK_SKEW_SECONDS = 60;

    /** Minimum interval between unknown-kid-triggered JWKS refreshes per URI (throttle). */
    private static final long DEFAULT_REFRESH_MIN_INTERVAL_MS = 30_000;

    /** Maximum age of cached JWKS before a mandatory re-fetch on next use. */
    private static final long CACHE_MAX_AGE_MS = 60 * 60 * 1000;

    private final Logger logger = LoggerFactory.getLogger(OidcIdTokenValidator.class);
    private final RestClientUtil restClientUtil;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final long refreshMinIntervalMs;

    private static final class CachedJwks {
        volatile Map<String, PublicKey> keys = Map.of();
        /** Timestamp of the last successful fetch (initial load or max-age re-fetch). */
        volatile long lastLoadEpochMs = 0;
        /**
         * Timestamp of the last unknown-kid-triggered refresh. Separate from
         * {@link #lastLoadEpochMs} so the initial load does not pre-empt the first
         * rotation refresh.
         */
        volatile long lastKidRefreshEpochMs = 0;
    }

    /** jwksUri -> holder. The holder is looked up without I/O; I/O happens inside refresh methods. */
    private final ConcurrentHashMap<String, CachedJwks> jwksCache = new ConcurrentHashMap<>();

    public OidcIdTokenValidator(RestClientUtil restClientUtil) {
        this(restClientUtil, DEFAULT_REFRESH_MIN_INTERVAL_MS);
    }

    /** Package-private constructor for tests that need a configurable throttle interval. */
    OidcIdTokenValidator(RestClientUtil restClientUtil, long refreshMinIntervalMs) {
        this.restClientUtil = restClientUtil;
        this.refreshMinIntervalMs = refreshMinIntervalMs;
    }

    /**
     * @return the verified claims, or empty if the signature, issuer, audience, exp presence,
     * or lifetime check fails. Never throws; never logs token contents.
     */
    public Optional<Claims> validate(String jwt, String jwksUri, String expectedIssuer, String expectedAudience) {
        try {
            Claims claims = Jwts.parser()
                    .keyLocator(header -> locateKey(jwksUri, header))
                    .requireIssuer(expectedIssuer)
                    .clockSkewSeconds(CLOCK_SKEW_SECONDS)
                    .build()
                    .parseSignedClaims(jwt)
                    .getPayload();

            if (claims.getExpiration() == null) {
                logger.error("JWT validation failed: missing exp claim");
                return Optional.empty();
            }

            Set<String> audience = claims.getAudience();
            if (audience == null || !audience.contains(expectedAudience)) {
                logger.error("JWT validation failed: audience does not contain the configured client id");
                return Optional.empty();
            }
            return Optional.of(claims);
        } catch (Exception e) {
            // Exception type only: messages can embed token fragments.
            logger.error("JWT validation failed: {}", e.getClass().getSimpleName());
            return Optional.empty();
        }
    }

    private Key locateKey(String jwksUri, Header header) {
        if (!(header instanceof ProtectedHeader protectedHeader)) {
            throw new JwtException("Unsigned JWTs are not accepted");
        }
        String kid = protectedHeader.getKeyId();

        // Cheap lookup: create holder without any I/O.
        CachedJwks cached = jwksCache.computeIfAbsent(jwksUri, uri -> new CachedJwks());

        long now = System.currentTimeMillis();
        boolean neverLoaded = cached.lastLoadEpochMs == 0;
        boolean stale = !neverLoaded && (now - cached.lastLoadEpochMs) > CACHE_MAX_AGE_MS;
        if (neverLoaded || stale) {
            // Initial load or max-age expiry: unconditional fetch (no kid-throttle applied).
            loadJwks(jwksUri, cached);
        }

        PublicKey key = cached.keys.get(kid);
        if (key == null) {
            // Unknown kid: possibly key rotation. Refresh once, throttled per refreshMinIntervalMs.
            // The throttle is tracked separately from the initial load so that a fresh initial load
            // does not prevent the very first rotation refresh.
            if ((now - cached.lastKidRefreshEpochMs) >= refreshMinIntervalMs) {
                refreshJwksOnUnknownKid(jwksUri, cached);
                key = cached.keys.get(kid);
            }
        }
        if (key == null) {
            throw new JwtException("No JWKS key found for token kid");
        }
        return key;
    }

    /**
     * Performs the initial load (or max-age re-fetch) without any throttle.
     * On network failure the holder's existing keys are preserved and the JwtException propagates.
     */
    private void loadJwks(String jwksUri, CachedJwks cached) {
        synchronized (cached) {
            // Another thread may have already loaded while we waited.
            if (cached.lastLoadEpochMs != 0
                    && (System.currentTimeMillis() - cached.lastLoadEpochMs) <= CACHE_MAX_AGE_MS) {
                return;
            }
            Map<String, PublicKey> freshKeys = fetchJwks(jwksUri);
            cached.keys = freshKeys;
            cached.lastLoadEpochMs = System.currentTimeMillis();
        }
    }

    /**
     * Refreshes the JWKS in response to an unknown kid, throttled to at most once per
     * {@link #refreshMinIntervalMs}. On network failure keys are preserved and JwtException propagates.
     */
    private void refreshJwksOnUnknownKid(String jwksUri, CachedJwks cached) {
        synchronized (cached) {
            // Another thread may have refreshed while we waited on the lock.
            if (System.currentTimeMillis() - cached.lastKidRefreshEpochMs < refreshMinIntervalMs) {
                return;
            }
            Map<String, PublicKey> freshKeys = fetchJwks(jwksUri);
            cached.keys = freshKeys;
            cached.lastKidRefreshEpochMs = System.currentTimeMillis();
            // Also update lastLoadEpochMs so we don't immediately re-fetch on next max-age check.
            cached.lastLoadEpochMs = cached.lastKidRefreshEpochMs;
        }
    }

    private Map<String, PublicKey> fetchJwks(String jwksUri) {
        try {
            ResponseEntity<String> resp = restClientUtil.retrieveGetResponse(jwksUri, new HttpHeaders());
            JsonNode jwks = objectMapper.readTree(Objects.requireNonNull(resp.getBody()));
            Map<String, PublicKey> keys = new HashMap<>();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            for (JsonNode jwk : jwks.path("keys")) {
                if (!"RSA".equals(jwk.path("kty").asText())) {
                    continue;
                }
                BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(jwk.path("n").asText()));
                BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(jwk.path("e").asText()));
                keys.put(jwk.path("kid").asText(), keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent)));
            }
            logger.info("Loaded {} RSA key(s) from JWKS endpoint", keys.size());
            return keys;
        } catch (Exception e) {
            logger.error("Failed to load JWKS from {}: {}", jwksUri, e.getClass().getSimpleName());
            throw new JwtException("Failed to load JWKS: " + e.getClass().getSimpleName(), e);
        }
    }
}
