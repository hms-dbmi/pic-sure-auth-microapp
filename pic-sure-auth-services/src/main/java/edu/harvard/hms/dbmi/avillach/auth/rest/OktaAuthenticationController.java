package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.service.auth.OktaOAuthAuthenticationService;
import io.swagger.annotations.Api;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.util.*;

@Api
@Path("/okta")
@Consumes("application/json")
@Produces("application/json")
public class OktaAuthenticationController {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Inject
    private OktaOAuthAuthenticationService oktaOAuthAuthenticationService;

    @POST
    @Path("/authentication")
    public Response authenticate(@Context HttpHeaders httpHeaders, @Context UriInfo uriInfo, HashMap<String, String> authRequest) {
        logger.info("OKTA LOGIN ATTEMPT ___ " + authRequest.get("email") + " ___");

        String idp_provider = JAXRSConfiguration.idp_provider;
        if (idp_provider.equalsIgnoreCase("okta")) {
            return oktaOAuthAuthenticationService.authenticate(uriInfo, authRequest);
        } else {
            return PICSUREResponse.error("IDP provider not configured correctly.x");
        }
    }

}
