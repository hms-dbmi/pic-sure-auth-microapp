package edu.harvard.hms.dbmi.avillach.auth.utils;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Utility for passing domain-specific audit metadata from services to the AuditLoggingFilter via request attributes. Uses request
 * attributes instead of a request-scoped bean to avoid proxy issues in the filter chain.
 */
public class AuditContext {

    private static final String ATTR_PREFIX = "audit.ctx.";

    private AuditContext() {}

    public static void put(HttpServletRequest request, String key, Object value) {
        if (request != null && key != null && value != null) {
            request.setAttribute(ATTR_PREFIX + key, value);
        }
    }

    public static Map<String, Object> getAll(HttpServletRequest request) {
        Map<String, Object> metadata = new HashMap<>();
        if (request == null) {
            return metadata;
        }
        Enumeration<String> names = request.getAttributeNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            if (name.startsWith(ATTR_PREFIX)) {
                metadata.put(name.substring(ATTR_PREFIX.length()), request.getAttribute(name));
            }
        }
        return metadata;
    }

    public static String extractClientIp(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    public static String extractSessionId(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String sessionHeader = request.getHeader("X-Session-Id");
        if (sessionHeader != null && !sessionHeader.isEmpty()) {
            return sessionHeader;
        }
        String ip = extractClientIp(request);
        String ua = request.getHeader("User-Agent");
        String raw = (ip != null ? ip : "") + "|" + (ua != null ? ua : "");
        return Integer.toHexString(raw.hashCode());
    }
}
