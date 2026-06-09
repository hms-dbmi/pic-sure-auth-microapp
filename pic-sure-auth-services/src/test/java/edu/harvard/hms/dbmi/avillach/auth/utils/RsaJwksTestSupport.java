package edu.harvard.hms.dbmi.avillach.auth.utils;

import io.jsonwebtoken.Jwts;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

/** Builds RSA keypairs, JWKS documents, and RS256-signed JWTs for OIDC validation tests. */
public final class RsaJwksTestSupport {

    private RsaJwksTestSupport() {}

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A JWKS document containing the single given public key under the given kid. */
    public static String jwksJson(String kid, RSAPublicKey publicKey) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String n = encoder.encodeToString(toUnsignedBytes(publicKey.getModulus()));
        String e = encoder.encodeToString(toUnsignedBytes(publicKey.getPublicExponent()));
        return "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"" + kid
                + "\",\"n\":\"" + n + "\",\"e\":\"" + e + "\"}]}";
    }

    /**
     * A JWKS document containing all keys in the given kid-to-key map plus an EC entry
     * with kid {@code "ec-1"} to verify that non-RSA entries are skipped without error.
     */
    public static String jwksJsonMulti(Map<String, RSAPublicKey> kidToKey) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        StringBuilder sb = new StringBuilder("{\"keys\":[");
        boolean first = true;
        for (Map.Entry<String, RSAPublicKey> entry : kidToKey.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            String n = encoder.encodeToString(toUnsignedBytes(entry.getValue().getModulus()));
            String e = encoder.encodeToString(toUnsignedBytes(entry.getValue().getPublicExponent()));
            sb.append("{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"")
              .append(entry.getKey())
              .append("\",\"n\":\"").append(n)
              .append("\",\"e\":\"").append(e)
              .append("\"}");
        }
        // Append a non-RSA (EC) entry that must be silently skipped.
        if (!first) sb.append(",");
        sb.append("{\"kty\":\"EC\",\"kid\":\"ec-1\",\"crv\":\"P-256\",\"x\":\"AAA\",\"y\":\"AAA\"}");
        sb.append("]}");
        return sb.toString();
    }

    public static String signedJwt(KeyPair keyPair, String kid, String issuer, String audience,
                                   String subject, Map<String, Object> extraClaims, Instant expiration) {
        return Jwts.builder()
                .header().keyId(kid).and()
                .claims(extraClaims)
                .issuer(issuer)
                .audience().add(audience).and()
                .subject(subject)
                .issuedAt(Date.from(Instant.now().minusSeconds(5)))
                .expiration(Date.from(expiration))
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();
    }

    /**
     * Builds an RS256 JWT with no {@code exp} claim — used to verify that exp-less tokens
     * are rejected.
     */
    public static String signedJwtNoExp(KeyPair keyPair, String kid, String issuer, String audience,
                                        String subject, Map<String, Object> extraClaims) {
        return Jwts.builder()
                .header().keyId(kid).and()
                .claims(extraClaims)
                .issuer(issuer)
                .audience().add(audience).and()
                .subject(subject)
                .issuedAt(Date.from(Instant.now().minusSeconds(5)))
                // no expiration
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();
    }

    private static byte[] toUnsignedBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }
}
