package edu.harvard.hms.dbmi.avillach.auth.utils;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AuditContextTest {

    @Test
    void shouldPutAndRetrieveMetadata() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        AuditContext.put(request, "key1", "value1");
        AuditContext.put(request, "key2", 42);

        Map<String, Object> all = AuditContext.getAll(request);
        assertEquals("value1", all.get("key1"));
        assertEquals(42, all.get("key2"));
        assertEquals(2, all.size());
    }

    @Test
    void shouldIgnoreNullKeyOrValue() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        AuditContext.put(request, null, "value");
        AuditContext.put(request, "key", null);

        Map<String, Object> all = AuditContext.getAll(request);
        assertTrue(all.isEmpty());
    }

    @Test
    void shouldIgnoreNullRequest() {
        AuditContext.put(null, "key", "value");
        Map<String, Object> all = AuditContext.getAll(null);
        assertTrue(all.isEmpty());
    }

    @Test
    void shouldNotIncludeNonAuditAttributes() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute("some.other.attr", "not-audit");
        AuditContext.put(request, "audit_key", "audit_value");

        Map<String, Object> all = AuditContext.getAll(request);
        assertEquals(1, all.size());
        assertEquals("audit_value", all.get("audit_key"));
    }
}
