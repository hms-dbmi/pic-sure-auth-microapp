package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import io.jsonwebtoken.Jwts;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Cryptographically verifies the RS256 signature of RAS passport / GA4GH visa JWTs against the
 * public keys RAS publishes at its JWKS endpoint.
 *
 * <p>Because Okta brokers the RAS connection, PIC-SURE never talks to RAS directly. Signature
 * verification against RAS's JWKS is therefore the only thing that guarantees the dbGaP permissions
 * carried in a passport were issued by RAS and were not tampered with anywhere in the Okta hop. The
 * keys are discovered via standard OIDC metadata ({@code <issuer>/.well-known/openid-configuration}
 * -> {@code jwks_uri}) and cached by {@code kid}; an unknown {@code kid} triggers a refresh to pick
 * up RAS key rotation.</p>
 */
@Service
public class RasPassportSignatureVerifier {

    private final Logger logger = LoggerFactory.getLogger(RasPassportSignatureVerifier.class);

    private final RestClientUtil restClientUtil;
    private final String issuer;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, PublicKey> keyCache = new ConcurrentHashMap<>();

    @Autowired
    public RasPassportSignatureVerifier(RestClientUtil restClientUtil,
                                        @Value("${ras.passport.issuer}") String rasPassportIssuer) {
        this.restClientUtil = restClientUtil;
        this.issuer = rasPassportIssuer == null ? null : rasPassportIssuer.replaceAll("/$", "");
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
            ResponseEntity<String> response = restClientUtil.retrieveGetResponse(jwksUri, new HttpHeaders());
            String body = logFetchDiagnostics("JWKS", jwksUri, response);
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
        ResponseEntity<String> response = restClientUtil.retrieveGetResponse(discoveryUrl, new HttpHeaders());
        String body = logFetchDiagnostics("OIDC discovery", discoveryUrl, response);
        JsonNode config = objectMapper.readTree(body);
        JsonNode jwksUri = config.get("jwks_uri");
        if (jwksUri == null) {
            throw new IllegalStateException("RAS OIDC discovery document has no jwks_uri at " + discoveryUrl);
        }
        return jwksUri.asText();
    }

    /**
     * Logs what we actually received for a RAS fetch so transport problems (truncation, compression,
     * proxy interference) are diagnosable without enabling DEBUG. Compare bodyLength against the
     * Content-Length header: a mismatch means the response was truncated before our JSON parser saw
     * it. The discovery/JWKS documents contain only public data (no secrets), so logging the body is
     * safe. Capped at 2048 chars to bound log size.
     */
    private String logFetchDiagnostics(String what, String url, ResponseEntity<String> response) {
        String body = response.getBody();
        String snippet = body == null ? "null" : body.substring(0, Math.min(2048, body.length()));
        logger.info("RAS {} fetch: url={} status={} contentLengthHeader={} contentEncoding={} transferEncoding={} bodyLength={} body={}",
                what, url, response.getStatusCode(),
                response.getHeaders().getFirst("Content-Length"),
                response.getHeaders().getFirst("Content-Encoding"),
                response.getHeaders().getFirst("Transfer-Encoding"),
                body == null ? "null" : body.length(),
                snippet);
        return body;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null ? null : value.asText();
    }
}
