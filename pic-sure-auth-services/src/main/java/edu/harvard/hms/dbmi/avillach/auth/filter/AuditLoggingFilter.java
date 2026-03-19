package edu.harvard.hms.dbmi.avillach.auth.filter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import edu.harvard.dbmi.avillach.logging.LoggingClient;
import edu.harvard.dbmi.avillach.logging.LoggingEvent;
import edu.harvard.dbmi.avillach.logging.RequestInfo;
import edu.harvard.hms.dbmi.avillach.auth.model.CustomApplicationDetails;
import edu.harvard.hms.dbmi.avillach.auth.model.CustomUserDetails;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuditContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@Order(2)
public class AuditLoggingFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(AuditLoggingFilter.class);

    private static final String AUDIT_START_TIME = "audit_start_time";

    private static final String DEST_IP;
    private static final Integer DEST_PORT;

    static {
        DEST_IP = System.getenv("DEST_IP");
        Integer port = null;
        String portStr = System.getenv("DEST_PORT");
        if (portStr != null) {
            try {
                port = Integer.parseInt(portStr);
            } catch (NumberFormatException e) {
                // ignore, will fallback to request
            }
        }
        DEST_PORT = port;
    }

    private static final Pattern AUTH_LOGIN = Pattern.compile("^/authentication/.+$");
    private static final Pattern TOKEN_INSPECT = Pattern.compile("^/token/inspect/?$");
    private static final Pattern USER_ME = Pattern.compile("^/user/me(/.*)?$");
    private static final Pattern USER_ADMIN = Pattern.compile("^/user/?$");
    private static final Pattern ROLE_ADMIN = Pattern.compile("^/role/?.*$");
    private static final Pattern PRIVILEGE_ADMIN = Pattern.compile("^/privilege/?.*$");
    private static final Pattern ACCESS_RULE_ADMIN = Pattern.compile("^/accessRule/?.*$");
    private static final Pattern TOS = Pattern.compile("^/tos/.*$");
    private static final Pattern STUDY_ACCESS = Pattern.compile("^/studyAccess/?.*$");

    private final LoggingClient loggingClient;

    @Autowired
    public AuditLoggingFilter(LoggingClient loggingClient) {
        this.loggingClient = loggingClient;
    }

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        request.setAttribute(AUDIT_START_TIME, System.currentTimeMillis());

        try {
            filterChain.doFilter(request, response);
        } finally {
            logRequest(request, response);
        }
    }

    private void logRequest(HttpServletRequest request, HttpServletResponse response) {
        try {
            if (loggingClient == null || !loggingClient.isEnabled()) {
                return;
            }

            String path = request.getRequestURI();

            // Strip context path (e.g., /auth)
            String contextPath = request.getContextPath();
            if (contextPath != null && !contextPath.isEmpty() && path.startsWith(contextPath)) {
                path = path.substring(contextPath.length());
            }

            // Skip paths that should not be logged
            if (
                path.startsWith("/actuator/") || path.endsWith("/swagger.yaml") || path.endsWith("/swagger.json")
                    || path.endsWith("/openapi.json")
            ) {
                return;
            }

            // Calculate duration
            Long startTime = (Long) request.getAttribute(AUDIT_START_TIME);
            long duration = 0L;
            if (startTime != null) {
                duration = System.currentTimeMillis() - startTime;
            }

            // Categorize event
            String method = request.getMethod();
            String eventType = "OTHER";
            String action = method;

            if (AUTH_LOGIN.matcher(path).matches() && "POST".equals(method)) {
                eventType = "AUTH";
                action = "LOGIN";
            } else if (path.equals("/logout")) {
                eventType = "AUTH";
                action = "LOGOUT";
            } else if (TOKEN_INSPECT.matcher(path).matches() && "POST".equals(method)) {
                eventType = "ACCESS";
                action = "TOKEN_INTROSPECT";
            } else if (USER_ME.matcher(path).matches() && "GET".equals(method)) {
                eventType = "ACCESS";
                action = "USER_PROFILE";
            } else if (USER_ADMIN.matcher(path).matches() && ("POST".equals(method) || "PUT".equals(method))) {
                eventType = "ADMIN";
                action = "USER_MODIFY";
            } else if (ROLE_ADMIN.matcher(path).matches() && ("POST".equals(method) || "PUT".equals(method))) {
                eventType = "ADMIN";
                action = "ROLE_MODIFY";
            } else if (PRIVILEGE_ADMIN.matcher(path).matches() && ("POST".equals(method) || "PUT".equals(method))) {
                eventType = "ADMIN";
                action = "PRIVILEGE_MODIFY";
            } else if (ACCESS_RULE_ADMIN.matcher(path).matches() && ("POST".equals(method) || "PUT".equals(method))) {
                eventType = "ADMIN";
                action = "ACCESS_RULE_MODIFY";
            } else if (TOS.matcher(path).matches()) {
                eventType = "ACCESS";
                action = "TOS";
            } else if (STUDY_ACCESS.matcher(path).matches() && ("POST".equals(method) || "PUT".equals(method))) {
                eventType = "ADMIN";
                action = "STUDY_ACCESS_MODIFY";
            }

            // Determine source IP
            String srcIp = AuditContext.extractClientIp(request);

            // Determine dest IP and port
            String destIp = DEST_IP != null ? DEST_IP : request.getLocalAddr();
            int destPort = DEST_PORT != null ? DEST_PORT : request.getLocalPort();

            // Response info
            int responseStatus = response.getStatus();
            String contentType = response.getContentType();

            // Build RequestInfo
            RequestInfo requestInfo = RequestInfo.builder().method(method).url(request.getRequestURI()).srcIp(srcIp).destIp(destIp)
                .destPort(destPort).httpUserAgent(request.getHeader("User-Agent")).status(responseStatus).duration(duration)
                .httpContentType(contentType).build();

            // Build metadata
            Map<String, Object> metadata = new HashMap<>();

            // Extract user info from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.getPrincipal() != null) {
                Object principal = authentication.getPrincipal();
                if (principal instanceof CustomUserDetails userDetails) {
                    metadata.put("user_id", userDetails.getUser().getUuid().toString());
                    if (userDetails.getUser().getEmail() != null) {
                        metadata.put("user_email", userDetails.getUser().getEmail());
                    }
                } else if (principal instanceof CustomApplicationDetails appDetails) {
                    if (appDetails.getApplication() != null) {
                        metadata.put("app_id", appDetails.getApplication().getUuid().toString());
                        metadata.put("app_name", appDetails.getApplication().getName());
                    }
                }
            }

            // Session ID
            metadata.put("session_id", AuditContext.extractSessionId(request));

            // Merge domain-specific metadata from AuditContext (set by services).
            // Filter-managed keys take precedence over AuditContext values.
            AuditContext.getAll(request).forEach(metadata::putIfAbsent);

            // Build error map for 4xx/5xx
            Map<String, Object> errorMap = null;
            if (responseStatus >= 400) {
                errorMap = new HashMap<>();
                errorMap.put("status", responseStatus);
                errorMap.put("error_type", responseStatus >= 500 ? "server_error" : "client_error");
            }

            // Build the event
            LoggingEvent.Builder eventBuilder = LoggingEvent.builder(eventType).action(action).request(requestInfo).metadata(metadata);

            if (errorMap != null) {
                eventBuilder.error(errorMap);
            }

            LoggingEvent event = eventBuilder.build();

            // Send the event with bearer token passthrough
            String authHeader = request.getHeader("Authorization");
            String requestId = request.getHeader("X-Request-Id");

            if (authHeader != null || requestId != null) {
                loggingClient.send(event, authHeader, requestId);
            } else {
                loggingClient.send(event);
            }

        } catch (Exception e) {
            logger.warn("AuditLoggingFilter failed to log request", e);
        }
    }

}
