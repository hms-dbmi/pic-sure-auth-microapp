package edu.harvard.hms.dbmi.avillach.auth.filter;

import edu.harvard.dbmi.avillach.logging.LoggingClient;
import edu.harvard.dbmi.avillach.logging.LoggingEvent;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuditContext;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuditLoggingFilterTest {

    private LoggingClient loggingClient;
    private AuditLoggingFilter filter;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        loggingClient = mock(LoggingClient.class);
        when(loggingClient.isEnabled()).thenReturn(true);
        filter = new AuditLoggingFilter(loggingClient);
        filterChain = mock(FilterChain.class);
    }

    @Test
    void shouldCategorizeLoginEvent() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/authentication/ras");
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setStatus(200);

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        LoggingEvent event = captor.getValue();
        assertEquals("AUTH", event.getEventType());
        assertEquals("auth.login", event.getAction());
    }

    @Test
    void shouldCategorizeLogoutEvent() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("AUTH", captor.getValue().getEventType());
        assertEquals("auth.logout", captor.getValue().getAction());
    }

    @Test
    void shouldCategorizeTokenIntrospect() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/token/inspect");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("ACCESS", captor.getValue().getEventType());
        assertEquals("token.introspect", captor.getValue().getAction());
    }

    @Test
    void shouldCategorizeUserProfile() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/user/me");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("ACCESS", captor.getValue().getEventType());
        assertEquals("user.profile", captor.getValue().getAction());
    }

    @Test
    void shouldCategorizeAdminUserModify() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/user");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("ADMIN", captor.getValue().getEventType());
        assertEquals("user.modify", captor.getValue().getAction());
    }

    @Test
    void shouldCategorizeRoleModify() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("PUT", "/role");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("ADMIN", captor.getValue().getEventType());
        assertEquals("role.modify", captor.getValue().getAction());
    }

    @Test
    void shouldCategorizeRoleDelete() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("DELETE", "/role/some-uuid");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("ADMIN", captor.getValue().getEventType());
        assertEquals("role.delete", captor.getValue().getAction());
    }

    @Test
    void shouldCategorizeConnectionModify() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/connection");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("ADMIN", captor.getValue().getEventType());
        assertEquals("connection.modify", captor.getValue().getAction());
    }

    @Test
    void shouldCategorizeConnectionDelete() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("DELETE", "/connection/some-uuid");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("ADMIN", captor.getValue().getEventType());
        assertEquals("connection.delete", captor.getValue().getAction());
    }

    @Test
    void shouldCategorizeApplicationModify() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("PUT", "/application");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("ADMIN", captor.getValue().getEventType());
        assertEquals("application.modify", captor.getValue().getAction());
    }

    @Test
    void shouldCategorizeApplicationTokenRefresh() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/application/refreshToken/some-uuid");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("ADMIN", captor.getValue().getEventType());
        assertEquals("application.token_refresh", captor.getValue().getAction());
    }

    @Test
    void shouldCategorizeTosAccept() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/tos/accept");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("ACCESS", captor.getValue().getEventType());
        assertEquals("tos.accept", captor.getValue().getAction());
    }

    @Test
    void shouldCategorizeTosUpdate() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/tos/update");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("ADMIN", captor.getValue().getEventType());
        assertEquals("tos.update", captor.getValue().getAction());
    }

    @Test
    void shouldCategorizeTokenRefresh() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/token/refresh");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("ACCESS", captor.getValue().getEventType());
        assertEquals("token.refresh", captor.getValue().getAction());
    }

    @Test
    void shouldCategorizeOpenAccessValidate() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/open/validate");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("ACCESS", captor.getValue().getEventType());
        assertEquals("open.validate", captor.getValue().getAction());
    }

    @Test
    void shouldCategorizeStudyAccessCreate() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/studyAccess");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("ADMIN", captor.getValue().getEventType());
        assertEquals("study_access.create", captor.getValue().getAction());
    }

    @Test
    void shouldCategorizeMappingDelete() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("DELETE", "/mapping/some-uuid");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("ADMIN", captor.getValue().getEventType());
        assertEquals("mapping.delete", captor.getValue().getAction());
    }

    @Test
    void shouldSkipActuatorHealth() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/health");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(loggingClient, never()).send(any(LoggingEvent.class));
    }

    @Test
    void shouldSkipSwagger() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/swagger.json");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(loggingClient, never()).send(any(LoggingEvent.class));
    }

    @Test
    void shouldNotLogWhenClientDisabled() throws Exception {
        when(loggingClient.isEnabled()).thenReturn(false);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/authentication/ras");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(loggingClient, never()).send(any(LoggingEvent.class));
    }

    @Test
    void shouldExtractClientIpFromXForwardedFor() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Forwarded-For", "1.2.3.4, 5.6.7.8");

        assertEquals("1.2.3.4", AuditContext.extractClientIp(request));
    }

    @Test
    void shouldFallbackToRemoteAddr() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.1");

        assertEquals("10.0.0.1", AuditContext.extractClientIp(request));
    }

    @Test
    void shouldUseSessionIdHeader() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Session-Id", "my-session-123");

        assertEquals("my-session-123", AuditContext.extractSessionId(request));
    }

    @Test
    void shouldGenerateSessionIdFromHash() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.1");
        request.addHeader("User-Agent", "Mozilla/5.0");

        String sessionId = AuditContext.extractSessionId(request);
        assertNotNull(sessionId);
        assertFalse(sessionId.isEmpty());
    }

    @Test
    void shouldIncludeSessionIdInMetadata() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some/endpoint");
        request.addHeader("X-Session-Id", "test-session");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("test-session", captor.getValue().getMetadata().get("session_id"));
    }

    @Test
    void shouldMergeAuditContextMetadata() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some/endpoint");
        AuditContext.put(request, "custom_field", "custom_value");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertEquals("custom_value", captor.getValue().getMetadata().get("custom_field"));
    }

    @Test
    void shouldPassBearerTokenThrough() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some/endpoint");
        request.addHeader("Authorization", "Bearer my-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(loggingClient).send(any(LoggingEvent.class), eq("Bearer my-token"), any());
    }

    @Test
    void shouldIncludeErrorMapFor4xx() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some/endpoint");
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setStatus(403);

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertNotNull(captor.getValue().getError());
        assertEquals("client_error", captor.getValue().getError().get("error_type"));
    }

    @Test
    void shouldIncludeErrorMapFor5xx() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some/endpoint");
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setStatus(500);

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<LoggingEvent> captor = ArgumentCaptor.forClass(LoggingEvent.class);
        verify(loggingClient).send(captor.capture());
        assertNotNull(captor.getValue().getError());
        assertEquals("server_error", captor.getValue().getError().get("error_type"));
    }
}
