package edu.harvard.hms.dbmi.avillach.auth.rest;

import com.okta.sdk.authc.credentials.TokenClientCredentials;
import com.okta.sdk.client.Client;
import com.okta.sdk.client.Clients;
import com.okta.sdk.resource.session.Session;
import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import io.swagger.annotations.Api;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.util.Map;

@Api
@Path("/okta")
@Consumes("application/json")
@Produces("application/json")
public class OktaAuthenticationService {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final String oktaDomain = System.getenv("okta_client_origin");
    private final String apiToken = System.getenv("okta_client_api_token");

    @GET
    @Path("/authentication")
    public Response authenticate(@Context HttpHeaders httpHeaders, @Context UriInfo uriInfo) {
        Client client = Clients.builder()
                .setOrgUrl(oktaDomain)
                .setClientCredentials(new TokenClientCredentials(apiToken))
                .build();

        Map<String, Cookie> cookies = httpHeaders.getCookies();

        // Print all of the cookies in the request
        for (Cookie cookie : cookies.values()) {
            logger.info("Cookie: " + cookie.getName() + " = " + cookie.getValue());
        }

        String oktaSessionID = null;
        // Look for the SID cookie for OKTA
        if (cookies.containsKey("sid")) {
            oktaSessionID = cookies.get("sid").getValue();
            logger.info("SID: " + oktaSessionID);
        }


        if (StringUtils.isNotBlank(oktaSessionID)) {
            // Check with OKTA if the user is authenticated
            Session session = client.getSession(oktaSessionID);

            if (session != null && session.getStatus() != null) {
                boolean isAuthenticated = session.getStatus().toString().equals("ACTIVE");

                return PICSUREResponse.success("Session is active: " + isAuthenticated);
            }
        }

        return PICSUREResponse.error("Session is not active");
    }
}
