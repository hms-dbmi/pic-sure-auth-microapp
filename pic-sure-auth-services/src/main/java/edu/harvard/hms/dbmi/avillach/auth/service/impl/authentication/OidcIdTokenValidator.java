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
 * endpoint. JWKS documents are cached per URI; an unseen {@code kid} triggers exactly one
 * refresh to pick up rotated keys. exp/iat are checked with a 60-second clock-skew leeway.
 */
@Service
public class OidcIdTokenValidator {

    private static final long CLOCK_SKEW_SECONDS = 60;

    private final Logger logger = LoggerFactory.getLogger(OidcIdTokenValidator.class);
    private final RestClientUtil restClientUtil;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /** jwksUri -> (kid -> public key). */
    private final ConcurrentHashMap<String, Map<String, PublicKey>> jwksCache = new ConcurrentHashMap<>();

    public OidcIdTokenValidator(RestClientUtil restClientUtil) {
        this.restClientUtil = restClientUtil;
    }

    /**
     * @return the verified claims, or empty if the signature, issuer, audience, or lifetime
     * check fails. Never throws; never logs token contents.
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

            Set<String> audience = claims.getAudience();
            if (audience == null || !audience.contains(expectedAudience)) {
                logger.error("JWT validation failed: audience does not contain the configured client id");
                return Optional.empty();
            }
            return Optional.of(claims);
        } catch (JwtException | IllegalArgumentException e) {
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
        Map<String, PublicKey> keys = jwksCache.computeIfAbsent(jwksUri, this::fetchJwks);
        PublicKey key = keys.get(kid);
        if (key == null) {
            // Unseen kid: likely key rotation. Refresh the document once.
            keys = jwksCache.compute(jwksUri, (uri, stale) -> fetchJwks(uri));
            key = keys.get(kid);
        }
        if (key == null) {
            throw new JwtException("No JWKS key found for token kid");
        }
        return key;
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
            throw new JwtException("Failed to load JWKS: " + e.getClass().getSimpleName(), e);
        }
    }
}
