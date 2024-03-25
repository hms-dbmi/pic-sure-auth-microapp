package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.hms.dbmi.avillach.auth.service.impl.AuthorizationService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.TokenService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;

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
@Api
@Controller("/token")
public class TokenController {

    private final TokenService tokenService;

    @Autowired
    public TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @ApiOperation(value = "Token introspection endpoint for user to retrieve a valid token")
    @PostMapping(path = "/inspect", produces = "application/json")
    public ResponseEntity<?> inspectToken(
            @ApiParam(required = true, value = "A JSON object that at least" +
                    " include a user the token for validation")
            Map<String, Object> inputMap) {
        return this.tokenService.inspectToken(inputMap);
    }

    @ApiOperation(value = "To refresh current user's token if the user is an active user")
    @GetMapping(path = "/refresh", produces = "application/json")
    public ResponseEntity<?> refreshToken(@RequestHeader("Authorization") String authorizationHeader) {
        return this.tokenService.refreshToken(authorizationHeader);
    }

}
