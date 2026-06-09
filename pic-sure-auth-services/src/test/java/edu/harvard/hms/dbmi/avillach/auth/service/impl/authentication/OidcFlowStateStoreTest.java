package edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class OidcFlowStateStoreTest {

    @Test
    public void storeAndConsume_roundTripsNonceAndVerifier() {
        OidcFlowStateStore store = new OidcFlowStateStore();
        String state = store.storeNewFlow("the-nonce", "the-verifier");

        assertNotNull(state);
        assertTrue(state.length() >= 32, "state should be a high-entropy token");

        Optional<OidcFlowStateStore.FlowState> flow = store.consume(state);
        assertTrue(flow.isPresent());
        assertEquals("the-nonce", flow.get().nonce());
        assertEquals("the-verifier", flow.get().codeVerifier());
    }

    @Test
    public void consume_isOneTimeUse() {
        OidcFlowStateStore store = new OidcFlowStateStore();
        String state = store.storeNewFlow("n", null);

        assertTrue(store.consume(state).isPresent());
        assertTrue(store.consume(state).isEmpty(), "second consume must fail");
    }

    @Test
    public void consume_rejectsUnknownNullAndBlankState() {
        OidcFlowStateStore store = new OidcFlowStateStore();
        assertTrue(store.consume("never-stored").isEmpty());
        assertTrue(store.consume(null).isEmpty());
        assertTrue(store.consume("  ").isEmpty());
    }

    @Test
    public void consume_rejectsExpiredFlow() {
        MutableClock clock = new MutableClock(Instant.parse("2026-06-09T00:00:00Z"));
        OidcFlowStateStore store = new OidcFlowStateStore(clock);
        String state = store.storeNewFlow("n", null);

        clock.advance(Duration.ofMinutes(11)); // TTL is 10 minutes
        assertTrue(store.consume(state).isEmpty());
    }

    @Test
    public void storeNewFlow_generatesUniqueStates() {
        OidcFlowStateStore store = new OidcFlowStateStore();
        assertNotEquals(store.storeNewFlow("a", null), store.storeNewFlow("b", null));
    }

    /** Minimal manually-advanced clock for TTL tests. */
    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) { this.now = start; }
        void advance(Duration d) { now = now.plus(d); }

        @Override public Instant instant() { return now; }
        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
    }
}
