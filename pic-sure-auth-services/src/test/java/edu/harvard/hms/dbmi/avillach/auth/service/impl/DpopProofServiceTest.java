package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.Jwks;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class DpopProofServiceTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final DpopProofService service = new DpopProofService();

    private JsonNode segment(String proof, int index) throws Exception {
        String[] parts = proof.split("\\.");
        return mapper.readTree(Base64.getUrlDecoder().decode(parts[index]));
    }

    @Test
    public void createProof_buildsDpopHeaderWithEcPublicJwk() throws Exception {
        String proof = service.createProof("POST", "https://example.okta.com/oauth2/v1/token", null, null);

        JsonNode header = segment(proof, 0);
        assertEquals("dpop+jwt", header.get("typ").asText());
        assertEquals("ES256", header.get("alg").asText());
        JsonNode jwk = header.get("jwk");
        assertEquals("EC", jwk.get("kty").asText());
        assertEquals("P-256", jwk.get("crv").asText());
        assertTrue(jwk.hasNonNull("x"));
        assertTrue(jwk.hasNonNull("y"));
    }

    @Test
    public void createProof_setsHtmHtuIatJti_andStripsQuery() throws Exception {
        String proof = service.createProof("GET", "https://example.okta.com/api/v1/x?foo=bar#frag", null, null);

        JsonNode claims = segment(proof, 1);
        assertEquals("GET", claims.get("htm").asText());
        assertEquals("https://example.okta.com/api/v1/x", claims.get("htu").asText());
        assertTrue(claims.hasNonNull("iat"));
        assertTrue(claims.hasNonNull("jti"));
        assertFalse(claims.has("nonce"));
        assertFalse(claims.has("ath"));
    }

    @Test
    public void createProof_addsNonceClaim_whenProvided() throws Exception {
        String proof = service.createProof("POST", "https://example.okta.com/oauth2/v1/token", "NONCE123", null);

        assertEquals("NONCE123", segment(proof, 1).get("nonce").asText());
    }

    @Test
    public void createProof_addsAthClaim_whenAccessTokenProvided() throws Exception {
        String token = "ACCESS_TOKEN";
        String proof = service.createProof("GET", "https://example.okta.com/api/v1/x", null, token);

        String expectedAth = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII)));
        assertEquals(expectedAth, segment(proof, 1).get("ath").asText());
    }

    @Test
    public void createProof_signatureVerifiesAgainstEmbeddedJwk() throws Exception {
        String proof = service.createProof("POST", "https://example.okta.com/oauth2/v1/token", null, null);

        String jwkJson = mapper.writeValueAsString(segment(proof, 0).get("jwk"));
        Jwk<?> jwk = Jwks.parser().build().parse(jwkJson);
        PublicKey pub = (PublicKey) jwk.toKey();

        // throws if the signature does not verify against the embedded public key
        assertDoesNotThrow(() -> Jwts.parser().verifyWith(pub).build().parseSignedClaims(proof));
    }
}
