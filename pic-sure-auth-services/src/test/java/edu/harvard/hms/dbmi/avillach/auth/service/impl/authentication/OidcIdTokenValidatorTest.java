package edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication;

import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import edu.harvard.hms.dbmi.avillach.auth.utils.RsaJwksTestSupport;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
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
        validator = new OidcIdTokenValidator(restClientUtil);
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
}
