package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Jwks;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

/**
 * Produces DPoP (RFC 9449) proof JWTs signed by a dedicated, ephemeral EC P-256 keypair generated
 * once per JVM. The keypair is used only for DPoP and is distinct from the RSA private_key_jwt
 * client-assertion key. Okta binds the minted access token to this key via the cnf.jkt claim.
 *
 * Never logs the private key or the proofs.
 */
@Service
public class DpopProofService {

    private final PrivateKey privateKey;
    /** Public key in JWK form (EcPublicJwk is a Map) embedded in every proof's "jwk" header. */
    private final Map<String, Object> publicJwk;

    public DpopProofService() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1")); // P-256
            KeyPair keyPair = kpg.generateKeyPair();
            this.privateKey = keyPair.getPrivate();
            this.publicJwk = Jwks.builder().key((ECPublicKey) keyPair.getPublic()).build();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to initialize DPoP keypair", ex);
        }
    }

    /**
     * Build a DPoP proof JWT.
     *
     * @param htm                 HTTP method of the target request (e.g. "POST", "GET")
     * @param htu                 target URL; query and fragment are stripped per RFC 9449
     * @param nonce               server-supplied DPoP nonce, or null/blank to omit
     * @param accessTokenForAth   access token to bind via the "ath" claim (resource calls), or null/blank to omit
     * @return the compact, signed proof JWT
     */
    public String createProof(String htm, String htu, String nonce, String accessTokenForAth) {
        String cleanHtu = (htu == null) ? null : htu.replaceAll("[?#].*$", "");
        long now = System.currentTimeMillis();
        JwtBuilder builder = Jwts.builder()
                .header().add("typ", "dpop+jwt").add("jwk", this.publicJwk).and()
                .claim("htm", htm)
                .claim("htu", cleanHtu)
                .issuedAt(new Date(now))
                .id(UUID.randomUUID().toString());
        if (nonce != null && !nonce.isBlank()) {
            builder.claim("nonce", nonce);
        }
        if (accessTokenForAth != null && !accessTokenForAth.isBlank()) {
            builder.claim("ath", base64UrlSha256(accessTokenForAth));
        }
        return builder.signWith(this.privateKey, Jwts.SIG.ES256).compact();
    }

    private static String base64UrlSha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.US_ASCII));
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex); // never happens on a standard JDK
        }
    }
}
