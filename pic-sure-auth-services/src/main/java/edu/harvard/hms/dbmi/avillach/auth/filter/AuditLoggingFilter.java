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

    // Auth patterns
    private static final Pattern AUTH_LOGIN = Pattern.compile("^/authentication/.+$");

    // Token patterns
    private static final Pattern TOKEN_INSPECT = Pattern.compile("^/token/inspect/?$");
    private static final Pattern TOKEN_REFRESH = Pattern.compile("^/token/refresh/?$");

    // User patterns
    private static final Pattern USER_ME = Pattern.compile("^/user/me(/.*)?$");
    private static final Pattern USER_ADMIN = Pattern.compile("^/user/?$");

    // Admin entity patterns (match both base path and path with ID)
    private static final Pattern ROLE_ADMIN = Pattern.compile("^/role(/[^/]+)?/?$");
    private static final Pattern PRIVILEGE_ADMIN = Pattern.compile("^/privilege(/[^/]+)?/?$");
    private static final Pattern ACCESS_RULE_ADMIN = Pattern.compile("^/accessRule(/[^/]+)?/?$");
    private static final Pattern APPLICATION_ADMIN = Pattern.compile("^/application(/[^/]+)?/?$");
    private static final Pattern APPLICATION_TOKEN_REFRESH = Pattern.compile("^/application/refreshToken/.+$");
    private static final Pattern CONNECTION_ADMIN = Pattern.compile("^/connection(/[^/]+)?/?$");
    private static final Pattern MAPPING_ADMIN = Pattern.compile("^/mapping(/[^/]+)?/?$");
    private static final Pattern STUDY_ACCESS = Pattern.compile("^/studyAccess/?.*$");

    // TOS patterns
    private static final Pattern TOS_ACCEPT = Pattern.compile("^/tos/accept/?$");
    private static final Pattern TOS_UPDATE = Pattern.compile("^/tos/update/?$");
    private static final Pattern TOS = Pattern.compile("^/tos(/.*)?$");

    // Open access
    private static final Pattern OPEN_VALIDATE = Pattern.compile("^/open/validate/?$");

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

            // Auth events
            if (AUTH_LOGIN.matcher(path).matches() && "POST".equals(method)) {
                eventType = "AUTH";
                action = "LOGIN";
            } else if (path.equals("/logout")) {
                eventType = "AUTH";
                action = "LOGOUT";

            // Token events
            } else if (TOKEN_INSPECT.matcher(path).matches() && "POST".equals(method)) {
                eventType = "ACCESS";
                action = "TOKEN_INTROSPECT";
            } else if (TOKEN_REFRESH.matcher(path).matches() && "GET".equals(method)) {
                eventType = "ACCESS";
                action = "TOKEN_REFRESH";

            // User events
            } else if (USER_ME.matcher(path).matches() && "GET".equals(method)) {
                eventType = "ACCESS";
                action = "USER_PROFILE";
            } else if (USER_ADMIN.matcher(path).matches() && isMutating(method)) {
                eventType = "ADMIN";
                action = "USER_MODIFY";

            // TOS events (check specific paths before generic)
            } else if (TOS_ACCEPT.matcher(path).matches() && "POST".equals(method)) {
                eventType = "ACCESS";
                action = "TOS_ACCEPT";
            } else if (TOS_UPDATE.matcher(path).matches() && "POST".equals(method)) {
                eventType = "ADMIN";
                action = "TOS_UPDATE";
            } else if (TOS.matcher(path).matches()) {
                eventType = "ACCESS";
                action = "TOS";

            // Open access
            } else if (OPEN_VALIDATE.matcher(path).matches() && "POST".equals(method)) {
                eventType = "ACCESS";
                action = "OPEN_ACCESS_VALIDATE";

            // Application events (check refreshToken before generic)
            } else if (APPLICATION_TOKEN_REFRESH.matcher(path).matches() && "GET".equals(method)) {
                eventType = "ADMIN";
                action = "APPLICATION_TOKEN_REFRESH";
            } else if (APPLICATION_ADMIN.matcher(path).matches() && isMutating(method)) {
                eventType = "ADMIN";
                action = "DELETE".equals(method) ? "APPLICATION_DELETE" : "APPLICATION_MODIFY";

            // Admin entity events
            } else if (ROLE_ADMIN.matcher(path).matches() && isMutating(method)) {
                eventType = "ADMIN";
                action = "DELETE".equals(method) ? "ROLE_DELETE" : "ROLE_MODIFY";
            } else if (PRIVILEGE_ADMIN.matcher(path).matches() && isMutating(method)) {
                eventType = "ADMIN";
                action = "DELETE".equals(method) ? "PRIVILEGE_DELETE" : "PRIVILEGE_MODIFY";
            } else if (ACCESS_RULE_ADMIN.matcher(path).matches() && isMutating(method)) {
                eventType = "ADMIN";
                action = "DELETE".equals(method) ? "ACCESS_RULE_DELETE" : "ACCESS_RULE_MODIFY";
            } else if (CONNECTION_ADMIN.matcher(path).matches() && isMutating(method)) {
                eventType = "ADMIN";
                action = "DELETE".equals(method) ? "CONNECTION_DELETE" : "CONNECTION_MODIFY";
            } else if (MAPPING_ADMIN.matcher(path).matches() && isMutating(method)) {
                eventType = "ADMIN";
                action = "DELETE".equals(method) ? "MAPPING_DELETE" : "MAPPING_MODIFY";
            } else if (STUDY_ACCESS.matcher(path).matches() && "POST".equals(method)) {
                eventType = "ADMIN";
                action = "STUDY_ACCESS_CREATE";
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

    private static boolean isMutating(String method) {
        return "POST".equals(method) || "PUT".equals(method) || "DELETE".equals(method);
    }

}
