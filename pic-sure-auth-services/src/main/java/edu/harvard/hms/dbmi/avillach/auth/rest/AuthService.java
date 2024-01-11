package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.service.auth.AuthenticationService;
import edu.harvard.hms.dbmi.avillach.auth.service.auth.FENCEAuthenticationService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.util.Map;

/**
 * <p>The authentication endpoint for PSAMA.</p>
 */
@Api
@Path("/")
@Consumes("application/json")
@Produces("application/json")
public class AuthService {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Inject
    AuthenticationService authenticationService;

    @Inject
    FENCEAuthenticationService fenceAuthenticationService;

    @ApiOperation(value = "The authentication endpoint for retrieving a valid user token")
    @POST
    @Path("/authentication")
    public Response authentication(@Context UriInfo uriInfo, @ApiParam(required = true, value = "A json object that includes all Oauth authentication needs, for example, access_token and redirectURI") Map<String, String> authRequest) {
        logger.debug("authentication() starting...");
        if (JAXRSConfiguration.idp_provider.equalsIgnoreCase("fence")) {
            logger.debug("authentication() FENCE authentication");
            return fenceAuthenticationService.getFENCEProfile("https://" + uriInfo.getBaseUri().getHost() + "/psamaui/login/", authRequest);
        } else {
            logger.debug("authentication() default authentication");
            return authenticationService.getToken(authRequest);
        }
    }
}
