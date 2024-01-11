package edu.harvard.hms.dbmi.avillach.auth.rest;

import com.okta.sdk.authc.credentials.TokenClientCredentials;
import com.okta.sdk.client.Client;
import com.okta.sdk.client.Clients;
import com.okta.sdk.resource.session.Session;
import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import io.swagger.annotations.Api;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.util.Map;

@Api
@Path("/okta")
@Consumes("application/json")
@Produces("application/json")
public class OktaAuthenticationService {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private JAXRSConfiguration config;

    @GET
    @Path("/authentication")
    public Response authenticate(@Context HttpHeaders httpHeaders, @Context UriInfo uriInfo) {
        if (StringUtils.isBlank(JAXRSConfiguration.oktaDomain) || StringUtils.isBlank(JAXRSConfiguration.oktaSessionApiToken)) {
            return PICSUREResponse.error("OKTA is not configured");
        }

        if (JAXRSConfiguration.oktaDomain.equalsIgnoreCase("disabled") || JAXRSConfiguration.oktaSessionApiToken.equalsIgnoreCase("disabled")) {
            return PICSUREResponse.error("OKTA is disabled");
        }

        Client client = Clients.builder()
                .setOrgUrl(JAXRSConfiguration.oktaDomain)
                .setClientCredentials(new TokenClientCredentials(JAXRSConfiguration.oktaSessionApiToken))
                .build();

        Map<String, Cookie> cookies = httpHeaders.getCookies();

        // Print all the cookies in the request, for debugging
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
