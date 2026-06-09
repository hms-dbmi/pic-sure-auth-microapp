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

    private static byte[] toUnsignedBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }
}
