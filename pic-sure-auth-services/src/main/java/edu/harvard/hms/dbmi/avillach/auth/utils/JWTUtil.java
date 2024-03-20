package edu.harvard.hms.dbmi.avillach.auth.utils;

import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.exceptions.NotAuthorizedException;
import io.jsonwebtoken.*;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

/**
 * <p>This class is for generating a JWT token and contains common methods for operations on JWT tokens.</p>
 * <p>For more information on JWT tokens, see <url>https://github.com/hms-dbmi/jwt-creator/blob/master/src/main/java/edu/harvard/hms/dbmi/avillach/jwt/App.java<url/></p>
 */
public class JWTUtil {
    private final static Logger logger = LoggerFactory.getLogger(JWTUtil.class);

    private static final long defaultTTLMillis = 1000L * 60 * 60 * 24 * 7;

    @Value("${application.client.secret}")
    private static String CLIENT_SECRET;

    /**
     * @param clientSecret
     * @param id
     * @param issuer
     * @param claims
     * @param subject
     * @param ttlMillis
     * @return
     */
    public static String createJwtToken(String clientSecret, String id, String issuer, Map<String, Object> claims, String subject, long ttlMillis) {
        logger.debug("createJwtToken() starting...");
        String jwt_token = null;

        if (ttlMillis < 0) {
            ttlMillis = defaultTTLMillis;
        }

        if (ttlMillis == 0) {
            ttlMillis = 999L * 1000 * 60 * 60 * 24;
        }

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        //We will sign our JWT with our ApiKey secret
        byte[] apiKeySecretBytes = clientSecret.getBytes();
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

        //Builds the JWT and serializes it to a compact, URL-safe string
        JwtBuilder builder = Jwts.builder()
                .setClaims(claims)
                .setId(id)
                .setIssuedAt(now)
                .setSubject(subject)
                .setIssuer(issuer)
                .signWith(signatureAlgorithm, signingKey);

        //if it has been specified, let's add the expiration
        long expMillis = nowMillis + ttlMillis;
        Date exp = new Date(expMillis);
        builder.setExpiration(exp);
        jwt_token = builder.compact();

        return jwt_token;
    }

    public static Jws<Claims> parseToken(String token) {
        Jws<Claims> jws = null;

        try {
            jws = Jwts.parser().setSigningKey(CLIENT_SECRET.getBytes(StandardCharsets.UTF_8)).parseClaimsJws(token);
        } catch (SignatureException e) {
            try {
                if (JAXRSConfiguration.clientSecretIsBase64.startsWith("true")) {
                    // handle if client secret is base64 encoded
                    jws = Jwts.parser().setSigningKey(Base64.decodeBase64(CLIENT_SECRET.getBytes(StandardCharsets.UTF_8))).parseClaimsJws(token);
                } else {
                    // handle if client secret is not base64 encoded
                    jws = Jwts.parser().setSigningKey(CLIENT_SECRET.getBytes(StandardCharsets.UTF_8)).parseClaimsJws(token);
                }
            } catch (JwtException | IllegalArgumentException ex) {
                logger.error("parseToken() throws: " + e.getClass().getSimpleName() + ", " + e.getMessage());
                throw new NotAuthorizedException(ex.getClass().getSimpleName() + ": " + ex.getMessage());
            }
        } catch (JwtException | IllegalArgumentException e) {
            logger.error("parseToken() throws: " + e.getClass().getSimpleName() + ", " + e.getMessage());
            throw new NotAuthorizedException(e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        if (jws == null) {
            logger.error("parseToken() get null for jws body by parsing Token - " + token);
            throw new NotAuthorizedException("Please contact admin to see the log");
        }

        return jws;
    }

    public static Optional<String> getTokenFromAuthorizationHeader(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return Optional.empty();
        }

        return Optional.of(authorizationHeader.substring("Bearer".length()).trim());
    }
}
