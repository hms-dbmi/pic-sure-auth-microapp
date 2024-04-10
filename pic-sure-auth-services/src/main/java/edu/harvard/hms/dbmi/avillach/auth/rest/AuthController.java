package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.hms.dbmi.avillach.auth.service.impl.AuthenticationService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.AuthorizationService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.FENCEAuthenticationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;
import java.util.Map;


/**
 * <p>The authentication endpoint for PSAMA.</p>
 */
@Tag(name = "Authentication")
@Controller
@RequestMapping("/")
public class AuthController {

    private final static Logger logger = LoggerFactory.getLogger(AuthController.class.getName());

    public final AuthorizationService authorizationService;

    public final AuthenticationService authenticationService;
    public final FENCEAuthenticationService fenceAuthenticationService;

    private final String idp_provider;

    @Autowired
    public AuthController(AuthorizationService authorizationService, AuthenticationService authenticationService, FENCEAuthenticationService fenceAuthenticationService, @Value("${application.idp.provider}") String idpProvider) {
        this.authorizationService = authorizationService;
        this.authenticationService = authenticationService;
        this.fenceAuthenticationService = fenceAuthenticationService;
        this.idp_provider = idpProvider;
    }

    @Operation(description = "The authentication endpoint for retrieving a valid user token")
    @PostMapping(path = "/authentication", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> authentication(@Parameter(required = true, description = "A json object that includes all Oauth authentication needs, for example, access_token and redirectURI") Map<String, String> authRequest) throws IOException {
        logger.debug("authentication() starting...");
        if (this.idp_provider.equalsIgnoreCase("fence")) {
            logger.debug("authentication() FENCE authentication");
            return fenceAuthenticationService.getFENCEProfile(authRequest);
        } else {
            logger.debug("authentication() default authentication");
            return authenticationService.getToken(authRequest);
        }
    }
}
