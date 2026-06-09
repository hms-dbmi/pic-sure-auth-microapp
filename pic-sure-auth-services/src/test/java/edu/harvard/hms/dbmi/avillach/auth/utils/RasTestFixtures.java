package edu.harvard.hms.dbmi.avillach.auth.utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Builders for realistic RAS test payloads: visa JWTs, passport JWTs, and userinfo documents. */
public final class RasTestFixtures {

    public static final String RAS_ISSUER = "https://stsstg.nih.gov";
    public static final String DBGAP_PHS_ID = "phs000007";
    public static final String DBGAP_CONSENT_GROUP = "c1";

    private static final javax.crypto.SecretKey TEST_KEY =
            Keys.hmacShaKeyFor("test-signing-key-test-signing-key-test!!".getBytes(StandardCharsets.UTF_8));

    private RasTestFixtures() {}

    /** A RAS dbGaP-permissions visa (GA4GH ControlledAccessGrants-style) as a compact JWT. */
    public static String dbgapVisaJwt(long expEpochSeconds) {
        Map<String, Object> visa = Map.of(
                "iss", RAS_ISSUER,
                "sub", "RAS-SUB-0123456789abcdef",
                "iat", Instant.now().getEpochSecond(),
                "exp", expEpochSeconds,
                "jti", "visa-jti-1",
                "txn", "txn-test-0001",
                "ga4gh_visa_v1", Map.of(
                        "type", "https://ras.nih.gov/visas/v1.1",
                        "asserted", Instant.now().getEpochSecond(),
                        "value", "https://stsstg.nih.gov/passport/dbgap/v1.1",
                        "source", "https://ncbi.nlm.nih.gov/gap",
                        "by", "dac"),
                "ras_dbgap_permissions", List.of(Map.of(
                        "consent_name", "General Research Use",
                        "phs_id", DBGAP_PHS_ID,
                        "version", "v1",
                        "participant_set", "p1",
                        "consent_group", DBGAP_CONSENT_GROUP,
                        "role", "pi",
                        "expiration", expEpochSeconds)));
        return Jwts.builder().claims(visa).signWith(TEST_KEY).compact();
    }

    /** A GA4GH LinkedIdentities visa as a compact JWT. */
    public static String linkedIdentitiesVisaJwt(long expEpochSeconds) {
        Map<String, Object> visa = Map.of(
                "iss", RAS_ISSUER,
                "sub", "RAS-SUB-0123456789abcdef",
                "iat", Instant.now().getEpochSecond(),
                "exp", expEpochSeconds,
                "jti", "visa-jti-2",
                "txn", "txn-test-0001",
                "ga4gh_visa_v1", Map.of(
                        "type", "LinkedIdentities",
                        "asserted", Instant.now().getEpochSecond(),
                        "value", "janeresearcher%40era.nih.gov,https%3A%2F%2Fstsstg.nih.gov",
                        "source", RAS_ISSUER,
                        "by", "system"));
        return Jwts.builder().claims(visa).signWith(TEST_KEY).compact();
    }

    /** The outer RAS passport JWT (payload = Passport model shape) wrapping the given visas. */
    public static String passportJwt(String issuer, long expEpochSeconds, List<String> visaJwts) {
        Map<String, Object> passport = Map.of(
                "sub", "RAS-SUB-0123456789abcdef",
                "jti", "passport-jti-1",
                "scope", "openid ga4gh_passport_v1",
                "txn", "txn-test-0001",
                "iss", issuer,
                "iat", Instant.now().getEpochSecond(),
                "exp", expEpochSeconds,
                "ga4gh_passport_v1", visaJwts);
        return Jwts.builder().claims(passport).signWith(TEST_KEY).compact();
    }

    /** Loads a fixture from src/test/resources/fixtures, substituting the passport placeholder. */
    public static String userinfoJson(String fixtureName, String passportJwt) {
        try (InputStream in = RasTestFixtures.class.getResourceAsStream("/fixtures/" + fixtureName)) {
            String json = new String(Objects.requireNonNull(in, "missing fixture " + fixtureName)
                    .readAllBytes(), StandardCharsets.UTF_8);
            return passportJwt == null ? json : json.replace("@@PASSPORT_JWT@@", passportJwt);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Convenience: a fully-valid userinfo document with a dbGaP visa and a LinkedIdentities visa. */
    public static String fullUserinfoJson() {
        long exp = Instant.now().getEpochSecond() + 12 * 60 * 60; // RAS passports/visas live 12h
        String passport = passportJwt(RAS_ISSUER, exp, List.of(dbgapVisaJwt(exp), linkedIdentitiesVisaJwt(exp)));
        return userinfoJson("ras-userinfo-full.json", passport);
    }
}
