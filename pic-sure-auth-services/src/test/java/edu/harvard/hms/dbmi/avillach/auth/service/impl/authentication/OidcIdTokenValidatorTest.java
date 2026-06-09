package edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication;

import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import edu.harvard.hms.dbmi.avillach.auth.utils.RsaJwksTestSupport;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class OidcIdTokenValidatorTest {

    private static final String JWKS_URI = "https://stsstg.nih.gov/openid/connect/jwks.json";
    private static final String ISSUER = "https://stsstg.nih.gov";
    private static final String CLIENT_ID = "picsure-client";

    private RestClientUtil restClientUtil;
    private OidcIdTokenValidator validator;
    private KeyPair keyPair;

    @BeforeEach
    public void setUp() {
        restClientUtil = mock(RestClientUtil.class);
        // Use throttle=0 for the standard validator so rotation test still works.
        validator = new OidcIdTokenValidator(restClientUtil, 0);
        keyPair = RsaJwksTestSupport.generateKeyPair();
    }

    private void stubJwks(String kid, KeyPair pair) {
        when(restClientUtil.retrieveGetResponse(eq(JWKS_URI), any(HttpHeaders.class)))
                .thenReturn(ResponseEntity.ok(RsaJwksTestSupport.jwksJson(kid, (RSAPublicKey) pair.getPublic())));
    }

    private String token(KeyPair pair, String kid, String issuer, String audience, Instant exp) {
        return RsaJwksTestSupport.signedJwt(pair, kid, issuer, audience, "user-sub",
                Map.of("nonce", "n-1", "acr", "https://stsstg.nih.gov/assurance/aal/2 https://stsstg.nih.gov/assurance/ial/2"),
                exp);
    }

    @Test
    public void validate_acceptsWellFormedToken() {
        stubJwks("kid-1", keyPair);
        String jwt = token(keyPair, "kid-1", ISSUER, CLIENT_ID, Instant.now().plusSeconds(300));

        Optional<Claims> claims = validator.validate(jwt, JWKS_URI, ISSUER, CLIENT_ID);

        assertTrue(claims.isPresent());
        assertEquals("user-sub", claims.get().getSubject());
        assertEquals("n-1", claims.get().get("nonce", String.class));
    }

    @Test
    public void validate_rejectsWrongIssuer() {
        stubJwks("kid-1", keyPair);
        String jwt = token(keyPair, "kid-1", "https://evil.example.com", CLIENT_ID, Instant.now().plusSeconds(300));

        assertTrue(validator.validate(jwt, JWKS_URI, ISSUER, CLIENT_ID).isEmpty());
    }

    @Test
    public void validate_rejectsWrongAudience() {
        stubJwks("kid-1", keyPair);
        String jwt = token(keyPair, "kid-1", ISSUER, "some-other-client", Instant.now().plusSeconds(300));

        assertTrue(validator.validate(jwt, JWKS_URI, ISSUER, CLIENT_ID).isEmpty());
    }

    @Test
    public void validate_rejectsExpiredTokenBeyondSkew() {
        stubJwks("kid-1", keyPair);
        String jwt = token(keyPair, "kid-1", ISSUER, CLIENT_ID, Instant.now().minusSeconds(120));

        assertTrue(validator.validate(jwt, JWKS_URI, ISSUER, CLIENT_ID).isEmpty());
    }

    @Test
    public void validate_acceptsTokenExpiredWithinSkew() {
        stubJwks("kid-1", keyPair);
        String jwt = token(keyPair, "kid-1", ISSUER, CLIENT_ID, Instant.now().minusSeconds(30));

        assertTrue(validator.validate(jwt, JWKS_URI, ISSUER, CLIENT_ID).isPresent(),
                "60s clock-skew leeway should accept a token expired 30s ago");
    }

    @Test
    public void validate_rejectsSignatureFromUnknownKey() {
        stubJwks("kid-1", keyPair);
        KeyPair attacker = RsaJwksTestSupport.generateKeyPair();
        String jwt = token(attacker, "kid-1", ISSUER, CLIENT_ID, Instant.now().plusSeconds(300));

        assertTrue(validator.validate(jwt, JWKS_URI, ISSUER, CLIENT_ID).isEmpty());
    }

    @Test
    public void validate_refreshesJwksOnUnknownKid_keyRotation() {
        KeyPair rotated = RsaJwksTestSupport.generateKeyPair();
        // First JWKS fetch returns the old key; the refresh (triggered by the unseen kid) returns the new one.
        when(restClientUtil.retrieveGetResponse(eq(JWKS_URI), any(HttpHeaders.class)))
                .thenReturn(ResponseEntity.ok(RsaJwksTestSupport.jwksJson("kid-old", (RSAPublicKey) keyPair.getPublic())))
                .thenReturn(ResponseEntity.ok(RsaJwksTestSupport.jwksJson("kid-new", (RSAPublicKey) rotated.getPublic())));

        // Prime the cache with the old document.
        String oldJwt = token(keyPair, "kid-old", ISSUER, CLIENT_ID, Instant.now().plusSeconds(300));
        assertTrue(validator.validate(oldJwt, JWKS_URI, ISSUER, CLIENT_ID).isPresent());

        String newJwt = token(rotated, "kid-new", ISSUER, CLIENT_ID, Instant.now().plusSeconds(300));
        assertTrue(validator.validate(newJwt, JWKS_URI, ISSUER, CLIENT_ID).isPresent(),
                "unknown kid should trigger one JWKS refresh");
        verify(restClientUtil, times(2)).retrieveGetResponse(eq(JWKS_URI), any(HttpHeaders.class));
    }

    @Test
    public void validate_rejectsGarbageToken() {
        stubJwks("kid-1", keyPair);
        assertTrue(validator.validate("not.a.jwt", JWKS_URI, ISSUER, CLIENT_ID).isEmpty());
        assertTrue(validator.validate(null, JWKS_URI, ISSUER, CLIENT_ID).isEmpty());
    }

    // -------------------------------------------------------------------------
    // New negative / edge-case tests
    // -------------------------------------------------------------------------

    @Test
    public void validate_rejectsHs256TokenSignedWithPublicKeyBytes() {
        stubJwks("kid-1", keyPair);
        // Derive 64 bytes from the RSA public key encoding to satisfy HMAC-SHA512 key length.
        byte[] hmacKeyBytes = Arrays.copyOf(keyPair.getPublic().getEncoded(), 64);
        String hs256Token = Jwts.builder()
                .header().keyId("kid-1").and()
                .claims(Map.of("k", "v"))
                .issuer(ISSUER)
                .audience().add(CLIENT_ID).and()
                .subject("user-sub")
                .expiration(Date.from(Instant.now().plusSeconds(300)))
                .signWith(Keys.hmacShaKeyFor(hmacKeyBytes), Jwts.SIG.HS256)
                .compact();

        assertTrue(validator.validate(hs256Token, JWKS_URI, ISSUER, CLIENT_ID).isEmpty(),
                "HS256 alg-confusion token must be rejected");
    }

    @Test
    public void validate_rejectsUnsignedAlgNoneToken() {
        // Build an alg=none token manually: base64url(header).base64url(payload).
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"kid\":\"kid-1\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(("{\"sub\":\"user-sub\",\"iss\":\"" + ISSUER + "\","
                        + "\"aud\":\"" + CLIENT_ID + "\","
                        + "\"exp\":" + (System.currentTimeMillis() / 1000 + 300) + "}").getBytes());
        String algNoneToken = header + "." + payload + ".";

        assertTrue(validator.validate(algNoneToken, JWKS_URI, ISSUER, CLIENT_ID).isEmpty(),
                "alg=none unsigned token must be rejected");
    }

    @Test
    public void validate_returnsEmptyWhenJwksFetchFails() {
        when(restClientUtil.retrieveGetResponse(eq(JWKS_URI), any(HttpHeaders.class)))
                .thenThrow(new RuntimeException("network error"));
        String jwt = token(keyPair, "kid-1", ISSUER, CLIENT_ID, Instant.now().plusSeconds(300));

        Optional<Claims> result = assertDoesNotThrow(
                () -> validator.validate(jwt, JWKS_URI, ISSUER, CLIENT_ID));
        assertTrue(result.isEmpty(), "JWKS fetch failure must return empty, not throw");
    }

    @Test
    public void validate_rejectsKidStillUnknownAfterRefresh() {
        // throttle=0 validator: always allow refreshes.
        OidcIdTokenValidator v = new OidcIdTokenValidator(restClientUtil, 0);
        // JWKS always returns kid-A, never kid-B.
        when(restClientUtil.retrieveGetResponse(eq(JWKS_URI), any(HttpHeaders.class)))
                .thenReturn(ResponseEntity.ok(RsaJwksTestSupport.jwksJson("kid-A", (RSAPublicKey) keyPair.getPublic())));

        // First validate with kid-A primes the cache (1 GET).
        String primeJwt = token(keyPair, "kid-A", ISSUER, CLIENT_ID, Instant.now().plusSeconds(300));
        assertTrue(v.validate(primeJwt, JWKS_URI, ISSUER, CLIENT_ID).isPresent());

        // Second validate with unknown kid-B triggers one more refresh then still fails (2 GETs total).
        KeyPair otherPair = RsaJwksTestSupport.generateKeyPair();
        String kidBJwt = token(otherPair, "kid-B", ISSUER, CLIENT_ID, Instant.now().plusSeconds(300));
        assertTrue(v.validate(kidBJwt, JWKS_URI, ISSUER, CLIENT_ID).isEmpty(),
                "kid-B is unknown even after refresh; must return empty");
        verify(restClientUtil, times(2)).retrieveGetResponse(eq(JWKS_URI), any(HttpHeaders.class));
    }

    @Test
    public void validate_throttlesRefreshStorm_defaultInterval() {
        // Use the default 30s throttle interval.
        OidcIdTokenValidator throttledValidator = new OidcIdTokenValidator(restClientUtil, 30_000);
        KeyPair rotated = RsaJwksTestSupport.generateKeyPair();
        // Priming fetch returns kid-A; any subsequent fetch would return kid-new.
        when(restClientUtil.retrieveGetResponse(eq(JWKS_URI), any(HttpHeaders.class)))
                .thenReturn(ResponseEntity.ok(RsaJwksTestSupport.jwksJson("kid-A", (RSAPublicKey) keyPair.getPublic())))
                .thenReturn(ResponseEntity.ok(RsaJwksTestSupport.jwksJson("kid-new", (RSAPublicKey) rotated.getPublic())));

        // Prime the cache (1 GET).
        String primeJwt = token(keyPair, "kid-A", ISSUER, CLIENT_ID, Instant.now().plusSeconds(300));
        assertTrue(throttledValidator.validate(primeJwt, JWKS_URI, ISSUER, CLIENT_ID).isPresent());

        // First unknown-kid validate: triggers refresh #2 (since lastRefresh was just now, throttle
        // will BLOCK on second consecutive unknown-kid within the 30s window).
        // Actually the first unknown-kid should attempt a refresh; then a second unknown-kid within
        // 30s should be throttled.  Here we just do two unknowns rapidly; the second must not fetch.
        String unknownJwt1 = token(rotated, "kid-unknown", ISSUER, CLIENT_ID, Instant.now().plusSeconds(300));
        assertTrue(throttledValidator.validate(unknownJwt1, JWKS_URI, ISSUER, CLIENT_ID).isEmpty());
        // Second unknown-kid within 30s: throttle must prevent a third GET.
        String unknownJwt2 = token(rotated, "kid-unknown2", ISSUER, CLIENT_ID, Instant.now().plusSeconds(300));
        assertTrue(throttledValidator.validate(unknownJwt2, JWKS_URI, ISSUER, CLIENT_ID).isEmpty());
        // Total GETs: 1 (prime) + 1 (first unknown-kid refresh) = 2, no more.
        verify(restClientUtil, times(2)).retrieveGetResponse(eq(JWKS_URI), any(HttpHeaders.class));
    }

    @Test
    public void validate_acceptsKeyFromMultiKeyJwksAndSkipsNonRsaEntries() {
        KeyPair keyPair2 = RsaJwksTestSupport.generateKeyPair();
        // Build a JWKS with two RSA keys and one EC entry.
        // LinkedHashMap preserves insertion order for predictability.
        Map<String, RSAPublicKey> kidToKey = new LinkedHashMap<>();
        kidToKey.put("kid-rsa-1", (RSAPublicKey) keyPair.getPublic());
        kidToKey.put("kid-rsa-2", (RSAPublicKey) keyPair2.getPublic());
        String multiJwks = RsaJwksTestSupport.jwksJsonMulti(kidToKey);
        when(restClientUtil.retrieveGetResponse(eq(JWKS_URI), any(HttpHeaders.class)))
                .thenReturn(ResponseEntity.ok(multiJwks));

        // Token signed by the SECOND RSA key should validate correctly.
        String jwt = token(keyPair2, "kid-rsa-2", ISSUER, CLIENT_ID, Instant.now().plusSeconds(300));
        Optional<Claims> result = assertDoesNotThrow(
                () -> validator.validate(jwt, JWKS_URI, ISSUER, CLIENT_ID));
        assertTrue(result.isPresent(), "Token under kid-rsa-2 must validate against multi-key JWKS");
        assertEquals("user-sub", result.get().getSubject());
    }

    @Test
    public void validate_rejectsTokenWithoutExp() {
        stubJwks("kid-1", keyPair);
        String noExpJwt = RsaJwksTestSupport.signedJwtNoExp(keyPair, "kid-1", ISSUER, CLIENT_ID,
                "user-sub", Map.of("nonce", "n-1"));

        assertTrue(validator.validate(noExpJwt, JWKS_URI, ISSUER, CLIENT_ID).isEmpty(),
                "Token without exp claim must be rejected");
    }
}
