package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.hms.dbmi.avillach.auth.service.AuthenticationService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.SessionService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication.AuthenticationServiceRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthenticationControllerTest {

    private AuthenticationServiceRegistry authenticationServiceRegistry;
    private AuthenticationController controller;
    private HttpServletRequest request;

    @BeforeEach
    public void setUp() {
        authenticationServiceRegistry = mock(AuthenticationServiceRegistry.class);
        controller = new AuthenticationController(authenticationServiceRegistry, mock(SessionService.class));
        request = mock(HttpServletRequest.class);
    }

    @Test
    public void authorizeUrl_returnsUrlForSupportingProvider() {
        AuthenticationService ras = mock(AuthenticationService.class);
        when(ras.getAuthorizeUrl("picsure.example.org"))
                .thenReturn(Optional.of("https://stsstg.nih.gov/auth/oauth/v2/authorize?response_type=code"));
        when(authenticationServiceRegistry.getAuthenticationService("ras")).thenReturn(ras);
        when(request.getServerName()).thenReturn("picsure.example.org");

        ResponseEntity<?> response = controller.authorizeUrl("ras", request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(Map.of("authorizeUrl", "https://stsstg.nih.gov/auth/oauth/v2/authorize?response_type=code"),
                response.getBody());
    }

    @Test
    public void authorizeUrl_returns404ForProviderWithoutServerSideAuthorize() {
        AuthenticationService fence = mock(AuthenticationService.class);
        when(fence.getAuthorizeUrl(anyString())).thenReturn(Optional.empty());
        when(authenticationServiceRegistry.getAuthenticationService("fence")).thenReturn(fence);
        when(request.getServerName()).thenReturn("picsure.example.org");

        assertEquals(HttpStatus.NOT_FOUND, controller.authorizeUrl("fence", request).getStatusCode());
    }

    @Test
    public void authorizeUrl_returns400ForUnknownProvider() {
        when(authenticationServiceRegistry.getAuthenticationService("nope"))
                .thenThrow(new IllegalArgumentException("No authentication service found for provider: nope"));

        assertEquals(HttpStatus.BAD_REQUEST, controller.authorizeUrl("nope", mock(HttpServletRequest.class)).getStatusCode());
    }
}
