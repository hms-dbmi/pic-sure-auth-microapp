package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that {@link RasPassportSignatureVerifier} cryptographically validates the RS256
 * signature of a RAS passport JWT against RAS's published JWKS, fetched via OIDC discovery.
 * The HTTP layer is replaced with a canned fetcher so the tests exercise real RSA verification.
 */
public class RasPassportSignatureVerifierTest {

    private static final String ISSUER = "https://stsstg.nih.gov";
    private static final String JWKS_URI = "https://stsstg.nih.gov/jwks";
    private static final String KID = "ras-test-key";

    private KeyPair rasKeyPair;
    private KeyPair attackerKeyPair;
    private RasPassportSignatureVerifier verifier;

    @BeforeEach
    public void setUp() throws Exception {
        rasKeyPair = generateKeyPair();
        attackerKeyPair = generateKeyPair();

        String jwks = buildJwksJson(KID, (RSAPublicKey) rasKeyPair.getPublic());
        RasPassportSignatureVerifier.UrlFetcher fetcher = url -> {
            if ((ISSUER + "/.well-known/openid-configuration").equals(url)) {
                return new RasPassportSignatureVerifier.FetchResult(
                        200, "HTTP_2", null, "{\"jwks_uri\":\"" + JWKS_URI + "\"}");
            }
            if (JWKS_URI.equals(url)) {
                return new RasPassportSignatureVerifier.FetchResult(200, "HTTP_2", null, jwks);
            }
            throw new IllegalArgumentException("unexpected url: " + url);
        };

        verifier = new RasPassportSignatureVerifier(ISSUER, fetcher);
    }

    @Test
    public void acceptsPassportSignedByPublishedKey() {
        String passport = signedJwt(KID, rasKeyPair.getPrivate(), "test-sub");

        assertTrue(verifier.isSignatureValid(passport),
                "A passport signed by RAS's published JWKS key must be accepted");
    }

    @Test
    public void rejectsPassportWithTamperedPayload() {
        // Same key + kid, but the payload is swapped after signing, so the signature no longer matches.
        String[] original = signedJwt(KID, rasKeyPair.getPrivate(), "real-sub").split("\\.");
        String[] forged = signedJwt(KID, rasKeyPair.getPrivate(), "attacker-sub").split("\\.");
        String tampered = forged[0] + "." + forged[1] + "." + original[2];

        assertFalse(verifier.isSignatureValid(tampered),
                "A passport whose payload was altered after signing must be rejected");
    }

    @Test
    public void rejectsPassportSignedByUnknownKey() {
        // Advertises the published kid, but is actually signed by a key RAS never published.
        String passport = signedJwt(KID, attackerKeyPair.getPrivate(), "attacker-sub");

        assertFalse(verifier.isSignatureValid(passport),
                "A passport signed by a key absent from RAS's JWKS must be rejected");
    }

    @Test
    public void rejectsWhenJwksBodyIsTruncated() {
        // Reproduces the production incident: the JWKS body comes back truncated mid-stream, so no
        // key can be loaded. Verification must fail closed rather than accept the passport.
        String validPassport = signedJwt(KID, rasKeyPair.getPrivate(), "test-sub");
        RasPassportSignatureVerifier.UrlFetcher truncating = url -> {
            if ((ISSUER + "/.well-known/openid-configuration").equals(url)) {
                return new RasPassportSignatureVerifier.FetchResult(
                        200, "HTTP_1_1", "1998", "{\"jwks_uri\":\"" + JWKS_URI + "\"}");
            }
            // JWKS truncated mid-field, exactly like the gateway-over-HTTP/1.1 failure.
            return new RasPassportSignatureVerifier.FetchResult(
                    200, "HTTP_1_1", "1998", "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"" + KID + "\",\"n");
        };
        RasPassportSignatureVerifier truncatedVerifier = new RasPassportSignatureVerifier(ISSUER, truncating);

        assertFalse(truncatedVerifier.isSignatureValid(validPassport),
                "A truncated/unparseable JWKS must cause verification to fail closed");
    }

    @Test
    public void rejectsPassportWithFakeSignature() {
        String[] parts = signedJwt(KID, rasKeyPair.getPrivate(), "test-sub").split("\\.");
        String fakeSigned = parts[0] + "." + parts[1] + ".fakesignature";

        assertFalse(verifier.isSignatureValid(fakeSigned),
                "A passport with a forged signature segment must be rejected");
    }

    @Test
    public void rejectsNonRs256SignedToken() {
        // Same key + kid, but signed with RS384. Verification must accept only RS256.
        String rs384 = Jwts.builder()
                .header().keyId(KID).and()
                .subject("test-sub").issuer(ISSUER)
                .issuedAt(new Date()).expiration(new Date(System.currentTimeMillis() + 3_600_000))
                .signWith(rasKeyPair.getPrivate(), Jwts.SIG.RS384)
                .compact();

        assertFalse(verifier.isSignatureValid(rs384), "Only RS256-signed passports may be accepted");
    }

    @Test
    public void rejectsTokenWithNoKid() {
        String noKid = Jwts.builder()
                .subject("test-sub").issuer(ISSUER)
                .issuedAt(new Date()).expiration(new Date(System.currentTimeMillis() + 3_600_000))
                .signWith(rasKeyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();

        assertFalse(verifier.isSignatureValid(noKid), "A token without a kid header must be rejected");
    }

    @Test
    public void rejectsWhenJwksFetchReturnsNon2xx() {
        RasPassportSignatureVerifier.UrlFetcher fetcher = url -> {
            if ((ISSUER + "/.well-known/openid-configuration").equals(url)) {
                return new RasPassportSignatureVerifier.FetchResult(200, "HTTP_2", null, "{\"jwks_uri\":\"" + JWKS_URI + "\"}");
            }
            return new RasPassportSignatureVerifier.FetchResult(503, "HTTP_2", null, "{\"error\":\"unavailable\"}");
        };
        RasPassportSignatureVerifier v = new RasPassportSignatureVerifier(ISSUER, fetcher);

        assertFalse(v.isSignatureValid(signedJwt(KID, rasKeyPair.getPrivate(), "test-sub")),
                "A non-2xx JWKS response must fail closed");
    }

    @Test
    public void doesNotRefetchJwksForRepeatedUnknownKid() {
        int[] jwksFetches = {0};
        RasPassportSignatureVerifier v = new RasPassportSignatureVerifier(ISSUER, countingFetcher(jwksFetches));
        // kid absent from the JWKS (e.g. rotated-out or forged).
        String unknownKid = signedJwt("rotated-out-kid", rasKeyPair.getPrivate(), "test-sub");

        assertFalse(v.isSignatureValid(unknownKid));
        assertFalse(v.isSignatureValid(unknownKid));

        assertEquals(1, jwksFetches[0],
                "Repeated verifications of an unknown kid must not refetch the JWKS each time (throttled)");
    }

    @Test
    public void refetchesJwksAfterTtl() {
        int[] jwksFetches = {0};
        AtomicLong clock = new AtomicLong(1_000_000L);
        RasPassportSignatureVerifier v = new RasPassportSignatureVerifier(ISSUER, countingFetcher(jwksFetches), clock::get);
        String valid = signedJwt(KID, rasKeyPair.getPrivate(), "test-sub");

        assertTrue(v.isSignatureValid(valid));
        assertTrue(v.isSignatureValid(valid));
        assertEquals(1, jwksFetches[0], "A cached key must be reused within the TTL");

        clock.addAndGet(RasPassportSignatureVerifier.CACHE_TTL_MS + 1);
        assertTrue(v.isSignatureValid(valid));
        assertEquals(2, jwksFetches[0], "After the TTL the JWKS must be re-pulled so rotated-out keys are dropped");
    }

    // ---- helpers ----

    private RasPassportSignatureVerifier.UrlFetcher countingFetcher(int[] jwksFetches) {
        String jwks = buildJwksJson(KID, (RSAPublicKey) rasKeyPair.getPublic());
        return url -> {
            if ((ISSUER + "/.well-known/openid-configuration").equals(url)) {
                return new RasPassportSignatureVerifier.FetchResult(200, "HTTP_2", null, "{\"jwks_uri\":\"" + JWKS_URI + "\"}");
            }
            if (JWKS_URI.equals(url)) {
                jwksFetches[0]++;
                return new RasPassportSignatureVerifier.FetchResult(200, "HTTP_2", null, jwks);
            }
            throw new IllegalArgumentException("unexpected url: " + url);
        };
    }

    private static String signedJwt(String kid, PrivateKey signingKey, String subject) {
        return Jwts.builder()
                .header().keyId(kid).and()
                .subject(subject)
                .issuer(ISSUER)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3_600_000))
                .signWith(signingKey, Jwts.SIG.RS256)
                .compact();
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static String buildJwksJson(String kid, RSAPublicKey key) {
        String n = base64Url(key.getModulus());
        String e = base64Url(key.getPublicExponent());
        return "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\""
                + kid + "\",\"n\":\"" + n + "\",\"e\":\"" + e + "\"}]}";
    }

    private static String base64Url(BigInteger value) {
        byte[] bytes = value.toByteArray();
        // Strip the sign byte BigInteger may prepend so the JWK encoding matches RFC 7518.
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            bytes = trimmed;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
