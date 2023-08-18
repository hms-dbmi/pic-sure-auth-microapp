package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.hms.dbmi.avillach.auth.service.auth.OpenAuthenticationService;
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
import javax.ws.rs.core.Response;
import java.util.Map;

/**
 * <p>The authentication endpoint for PSAMA.</p>
 */
@Api
@Path("/open")
@Consumes("application/json")
@Produces("application/json")
public class OpenAuthService {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Inject
    private OpenAuthenticationService openAuthenticationService;

    @ApiOperation(value = "The authentication endpoint for retrieving a valid user token")
    @POST
    @Path("/authentication")
    public Response authentication(@ApiParam(required = true, value = "A json object that includes all Oauth authentication needs, for example, access_token and redirectURI") Map<String, String> authRequest) {
        logger.debug("authentication() starting...");

        return openAuthenticationService.authenticate(authRequest);
    }

}
