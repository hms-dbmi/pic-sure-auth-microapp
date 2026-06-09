package edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication;

import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * One-time store for in-flight OIDC authorization flows, keyed by the generated {@code state}
 * parameter. The state value provides CSRF protection for the authorization callback; the stored
 * nonce binds the eventual ID token to this flow; the stored code verifier supports PKCE when the
 * IDP advertises it. Entries are single-use and expire after {@link #TTL}.
 *
 * In-memory by design: PSAMA is deployed as a single instance per environment. If that changes,
 * this store must move to a shared backend.
 */
@Service
public class OidcFlowStateStore {

    public record FlowState(String nonce, String codeVerifier, Instant createdAt) {}

    static final Duration TTL = Duration.ofMinutes(10);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final ConcurrentHashMap<String, FlowState> flows = new ConcurrentHashMap<>();
    private final Clock clock;

    public OidcFlowStateStore() {
        this(Clock.systemUTC());
    }

    OidcFlowStateStore(Clock clock) {
        this.clock = clock;
    }

    /** Stores a new flow and returns its generated state value. codeVerifier may be null (no PKCE). */
    public String storeNewFlow(String nonce, String codeVerifier) {
        evictExpired();
        String state = randomToken();
        flows.put(state, new FlowState(nonce, codeVerifier, Instant.now(clock)));
        return state;
    }

    /** Removes and returns the flow for this state. Empty if unknown, already used, or expired. */
    public Optional<FlowState> consume(String state) {
        if (state == null || state.isBlank()) {
            return Optional.empty();
        }
        FlowState flow = flows.remove(state);
        if (flow == null || isExpired(flow)) {
            return Optional.empty();
        }
        return Optional.of(flow);
    }

    /** 256 bits of SecureRandom, base64url without padding — suitable for state, nonce, and PKCE verifiers. */
    public static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private boolean isExpired(FlowState flow) {
        return flow.createdAt().plus(TTL).isBefore(Instant.now(clock));
    }

    private void evictExpired() {
        flows.entrySet().removeIf(entry -> isExpired(entry.getValue()));
    }
}
