package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.entity.ApiKey;
import edu.harvard.hms.dbmi.avillach.auth.enums.ApiKeyType;
import edu.harvard.hms.dbmi.avillach.auth.model.response.ApiKeyCreationResponse;
import edu.harvard.hms.dbmi.avillach.auth.model.response.ApiKeyMetadata;
import edu.harvard.hms.dbmi.avillach.auth.repository.ApiKeyRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Generates, verifies, and manages API keys for open-access requests. Only a hash of each key is
 * stored; the plaintext exists solely in the {@link ApiKeyCreationResponse} returned at creation.
 */
@Service
public class ApiKeyService {

    private static final Logger logger = LoggerFactory.getLogger(ApiKeyService.class);

    public static final String KEY_PREFIX = "picsure_";
    public static final String SCHEME_SHA256 = "SHA256";
    public static final String SCHEME_HMAC_SHA256 = "HMAC_SHA256";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    // 43 base62 characters carry just under 256 bits of entropy
    private static final int KEY_BODY_LENGTH = 43;
    private static final int DISPLAY_PREFIX_LENGTH = 8;
    private static final Duration LAST_USED_WRITE_INTERVAL = Duration.ofMinutes(1);

    private final ApiKeyRepository apiKeyRepository;
    private final String pepper;
    private final List<String> previousPeppers;
    private final long userKeyTtlDays;

    @Autowired
    public ApiKeyService(
        ApiKeyRepository apiKeyRepository, @Value("${api.key.pepper}") String pepper,
        @Value("${api.key.pepper.previous}") String previousPeppers, @Value("${api.key.user.ttl.days}") long userKeyTtlDays
    ) {
        if (userKeyTtlDays <= 0) {
            throw new IllegalStateException("api.key.user.ttl.days must be positive, was " + userKeyTtlDays);
        }
        this.apiKeyRepository = apiKeyRepository;
        this.pepper = pepper;
        this.previousPeppers = previousPeppers == null ? List.of()
            : Arrays.stream(previousPeppers.split(",")).map(String::trim).filter(ApiKeyService::isSet).toList();
        this.userKeyTtlDays = userKeyTtlDays;
    }

    public ApiKeyCreationResponse generateUserKey(String email) {
        return generate(ApiKeyType.USER, null, email, null);
    }

    public ApiKeyCreationResponse generatePlatformKey(String name, String email, Instant expiresAt) {
        return generate(ApiKeyType.PLATFORM, name, email, expiresAt);
    }

    private ApiKeyCreationResponse generate(ApiKeyType keyType, String name, String email, Instant expiresAt) {
        Instant createdAt = Instant.now();
        if (expiresAt == null) {
            expiresAt = createdAt.plus(userKeyTtlDays, ChronoUnit.DAYS);
        }
        if (!expiresAt.isAfter(createdAt)) {
            throw new IllegalArgumentException("API key expiration must be in the future");
        }
        String body = randomBase62(KEY_BODY_LENGTH);
        String plaintext = KEY_PREFIX + body;
        ApiKey apiKey = new ApiKey().setKeyHash(hashWithCurrentScheme(plaintext)).setHashScheme(currentScheme())
            .setDisplayPrefix(body.substring(0, DISPLAY_PREFIX_LENGTH)).setKeyType(keyType).setName(name).setEmail(email)
            .setCreatedAt(createdAt).setExpiresAt(expiresAt);
        apiKey = apiKeyRepository.save(apiKey);
        logger.info("Generated {} API key {} with display prefix {}", keyType, apiKey.getUuid(), apiKey.getDisplayPrefix());
        return new ApiKeyCreationResponse(plaintext, apiKey.getUuid(), apiKey.getDisplayPrefix(), keyType, expiresAt);
    }

    /**
     * Verifies a presented key: indexed hash lookup, then revocation and expiry checks.
     * Returns the matching entity only when the key is currently valid.
     */
    public Optional<ApiKey> verifyKey(String plaintext) {
        if (plaintext == null || !plaintext.startsWith(KEY_PREFIX)) {
            return Optional.empty();
        }

        Optional<ApiKey> found = findUnderAnyActiveScheme(plaintext);
        if (found.isEmpty()) {
            return Optional.empty();
        }

        ApiKey apiKey = found.get();
        Instant now = Instant.now();
        if (apiKey.getRevokedAt() != null || !now.isBefore(apiKey.getExpiresAt())) {
            logger.info(
                "Rejected {} API key with display prefix {}: {}", apiKey.getKeyType(), apiKey.getDisplayPrefix(),
                apiKey.getRevokedAt() != null ? "revoked" : "expired"
            );
            return Optional.empty();
        }

        touchLastUsed(apiKey, now);
        return Optional.of(apiKey);
    }

    public List<ApiKeyMetadata> listKeys() {
        return apiKeyRepository.findAllByOrderByCreatedAtDesc().stream().map(ApiKeyMetadata::from).toList();
    }

    public Optional<ApiKeyMetadata> revokeKey(UUID uuid) {
        return apiKeyRepository.findById(uuid).map(apiKey -> {
            if (apiKey.getRevokedAt() == null) {
                apiKey.setRevokedAt(Instant.now());
                apiKey = apiKeyRepository.save(apiKey);
                logger.info("Revoked API key {} with display prefix {}", apiKey.getUuid(), apiKey.getDisplayPrefix());
            }
            return ApiKeyMetadata.from(apiKey);
        });
    }

    /**
     * Tries the current pepper, then each previous pepper (covering rotation, oldest keys last),
     * then the unpeppered scheme (covering keys minted before a pepper was configured). Unset
     * peppers are skipped, so HMAC-backed keys still verify while the current pepper is
     * accidentally omitted, as long as it appears in the previous-pepper list.
     */
    private Optional<ApiKey> findUnderAnyActiveScheme(String plaintext) {
        List<String> activePeppers = new ArrayList<>();
        if (hasPepper()) {
            activePeppers.add(pepper);
        }
        activePeppers.addAll(previousPeppers);
        for (String activePepper : activePeppers) {
            Optional<ApiKey> found = apiKeyRepository.findByKeyHash(hmacSha256(activePepper, plaintext))
                .filter(key -> SCHEME_HMAC_SHA256.equals(key.getHashScheme()));
            if (found.isPresent()) {
                return found;
            }
        }
        return apiKeyRepository.findByKeyHash(sha256(plaintext)).filter(key -> SCHEME_SHA256.equals(key.getHashScheme()));
    }

    // last_used_at is usage telemetry, not an audit trail; throttling avoids a DB write per request
    // and a failed write must not reject an otherwise valid key
    private void touchLastUsed(ApiKey apiKey, Instant now) {
        if (apiKey.getLastUsedAt() == null || apiKey.getLastUsedAt().isBefore(now.minus(LAST_USED_WRITE_INTERVAL))) {
            try {
                apiKeyRepository.touchLastUsed(apiKey.getUuid(), now);
            } catch (RuntimeException e) {
                logger.warn("Failed to update last_used_at for API key with display prefix {}", apiKey.getDisplayPrefix(), e);
            }
        }
    }

    private boolean hasPepper() {
        return isSet(pepper);
    }

    private static boolean isSet(String value) {
        return value != null && !value.isBlank();
    }

    private String currentScheme() {
        return hasPepper() ? SCHEME_HMAC_SHA256 : SCHEME_SHA256;
    }

    private String hashWithCurrentScheme(String plaintext) {
        return hasPepper() ? hmacSha256(pepper, plaintext) : sha256(plaintext);
    }

    private static String sha256(String plaintext) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(plaintext.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String hmacSha256(String pepper, String plaintext) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(pepper.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    private static String randomBase62(int length) {
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(BASE62_ALPHABET.charAt(SECURE_RANDOM.nextInt(BASE62_ALPHABET.length())));
        }
        return builder.toString();
    }
}
