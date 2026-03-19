package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.dbmi.avillach.logging.LoggingClient;
import edu.harvard.dbmi.avillach.logging.LoggingEvent;
import edu.harvard.hms.dbmi.avillach.auth.model.InvalidRefreshToken;
import edu.harvard.hms.dbmi.avillach.auth.model.RefreshToken;
import edu.harvard.hms.dbmi.avillach.auth.model.ValidRefreshToken;
import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.authorization.AuthorizationService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.TokenService;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuditContext;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * <p>Token introspection endpoint called by an application to validate a user's token and permissions by request.</p>
 *
 * <p>Here, a registered application asks if the user behind a token is allowed to perform certain activities by
 * showing this endpoint the token and where the user wants to go.</p>
 * <p>To accomplish this, this endpoint validates the incoming token, then checks if the user behind the token
 * is authorized to access the URLs they queried and send data along with them. The AuthorizationService class handles authorization
 * {@link AuthorizationService} at the access rule level, but this endpoint handles token validation and pre-check at the privilege level.</p>
 */
@Tag(name = "Token Management")
@Controller
@RequestMapping("/token")
public class TokenController {

    private final TokenService tokenService;
    private final LoggingClient loggingClient;

    @Autowired
    public TokenController(TokenService tokenService, LoggingClient loggingClient) {
        this.tokenService = tokenService;
        this.loggingClient = loggingClient;
    }

    @Operation(description = "Token introspection endpoint for user to retrieve a valid token")
    @PostMapping(path = "/inspect", produces = "application/json")
    public ResponseEntity<Map<String, Object>> inspectToken(
            @Parameter(required = true, description = "A JSON object that at least" +
                    " include a user the token for validation")
            @RequestBody Map<String, Object> inputMap, HttpServletRequest request) {
        Map<String, Object> stringObjectMap = this.tokenService.inspectToken(inputMap);

        loggingClient.send(LoggingEvent.builder("ACCESS")
            .action("TOKEN_INTROSPECT")
            .metadata(Map.of(
                "active", String.valueOf(stringObjectMap.getOrDefault("active", false))
            ))
            .build());

        AuditContext.put(request, "token_active", String.valueOf(stringObjectMap.getOrDefault("active", false)));
        return PICSUREResponse.success(stringObjectMap);
    }

    @Operation(description = "To refresh current user's token if the user is an active user")
    @GetMapping(path = "/refresh", produces = "application/json")
    public ResponseEntity<?> refreshToken(@RequestHeader("Authorization") String authorizationHeader) {
        RefreshToken refreshTokenResp = this.tokenService.refreshToken(authorizationHeader);

        if (refreshTokenResp instanceof InvalidRefreshToken invalidRefreshToken) {
            return PICSUREResponse.protocolError(invalidRefreshToken.error());
        }

        if (refreshTokenResp instanceof ValidRefreshToken validRefreshToken) {
            return PICSUREResponse.success(Map.of("token", validRefreshToken.token(), "expirationDate", validRefreshToken.expirationDate()));
        }

        return PICSUREResponse.success();
    }

}
