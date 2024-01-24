package edu.harvard.hms.dbmi.avillach.auth.service.auth;

import com.fasterxml.jackson.databind.JsonNode;
import edu.harvard.dbmi.avillach.util.HttpClientUtil;
import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.Role;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.RoleRepository;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.UserRepository;
import edu.harvard.hms.dbmi.avillach.auth.rest.UserService;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.util.*;

public class OktaOAuthAuthenticationService {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Inject
    private UserRepository userRepository;

    @Inject
    private RoleRepository roleRepository;

    @Inject
    private AuthUtils authUtil;

    /**
     * Authenticate the user using the code provided by the IDP. This code is exchanged for an access token.
     * The access token is then used to introspect the user. The user is then loaded from the database.
     * If the user does not exist, we will reject their login attempt.
     *
     * @param uriInfo     The UriInfo object from the JAX-RS context
     * @param authRequest The request body
     * @return The response from the authentication attempt
     */
    public Response authenticate(UriInfo uriInfo, Map<String, String> authRequest) {
        String code = authRequest.get("code");
        if (StringUtils.isNotBlank(code)) {
            JsonNode userToken = handleCodeTokenExchange(uriInfo, code);
            logger.info("UserToken: " + userToken);
            JsonNode introspectResponse = introspectToken(userToken);

            if (introspectResponse == null) {
                return PICSUREResponse.error("Failed to introspect access token.");
            }

            logger.info("Introspection Token: " + introspectResponse);

            User user = initializeUser(introspectResponse);
            if (user == null) {
                logger.info("LOGIN FAILED ___ USER NOT FOUND ___ " + userToken.get("email").asText() + ":" + userToken.get("sub").asText() + " ___");
                return PICSUREResponse.error("User not found");
            }

            HashMap<String, String> responseMap = createUserClaims(user);
            logger.info("LOGIN SUCCESS ___ " + user.getEmail() + ":" + user.getUuid().toString() + " ___ Authorization will expire at  ___ " + responseMap.get("expirationDate") + "___");

            return PICSUREResponse.success(responseMap);
        }

        logger.info("LOGIN FAILED ___ USER FAILED TO AUTHENTICATE ___");
        return PICSUREResponse.error("User not authenticated");
    }

    private User initializeUser(JsonNode introspectResponse) {
        boolean isActive = introspectResponse.get("active").asBoolean();
        if (!isActive) {
            logger.info("LOGIN FAILED ___ USER IS NOT ACTIVE ___ ");
            return null;
        }

        User user = loadUser(introspectResponse);
        clearCache(user);
        user = addUserRoles(user);
        return user;
    }

    private HashMap<String, String> createUserClaims(User user) {
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("name", user.getName());
        claims.put("email", user.getEmail());
        claims.put("sub", user.getSubject());
        return authUtil.getUserProfileResponse(claims);
    }


    private User addUserRoles(User user) {
        Role openAccessRole = roleRepository.getUniqueResultByColumn("name", FENCEAuthenticationService.fence_open_access_role_name);
        return userRepository.createOpenAccessUser(openAccessRole);
    }

    private void clearCache(User user) {
        AuthorizationService.clearCache(user);
        UserService.clearCache(user);
    }

    /**
     * Using the introspection token response, load the user from the database. If the user does not exist, we
     * will reject their login attempt.
     * Documentation: <a href="https://developer.okta.com/docs/reference/api/oidc/#response-example-success-access-token">response-example-success-access-token</a>
     *
     * @param introspectResponse The response from the introspect endpoint
     * @return The user
     */
    private User loadUser(JsonNode introspectResponse) {
        String email = introspectResponse.get("username").asText();
        // TODO: Load the user from the database. For now, just return a new user so we can test.
        User user = new User();
        user.setSubject(introspectResponse.get("sub").asText());
        user.setEmail(email);
        user.setConnection(null); // TODO: We need to load the connection from the database.
        user.setAcceptedTOS(new Date());
        user.setGeneralMetadata(introspectResponse.toString());
        user.setActive(introspectResponse.get("active").asBoolean());

        return user;
    }

    /**
     * Introspect the token to get the user's email address. This is a call to the OKTA introspect endpoint.
     *
     * @param userToken The token to introspect
     * @return The response from the introspect endpoint as a JsonNode
     */
    private JsonNode introspectToken(JsonNode userToken) {
        if (!userToken.has("access_token")) {
            return null;
        }
        String accessToken = userToken.get("access_token").toString();
        logger.info("introspectToken - Access Token: " + accessToken);
        String oktaIntrospectUrl = "https://" + JAXRSConfiguration.idp_provider_uri + "/oauth2/default/v1/introspect";
        String queryString = "token=" + accessToken + "&token_type_hint=access_token";
        String contentType = "application/json";

        return doOktaRequest(oktaIntrospectUrl, queryString, contentType);
    }

    /**
     * Exchange the code for an access token. This is a call to the OKTA token endpoint.
     * Documentation: <a href="https://developer.okta.com/docs/reference/api/oidc/#token">Token</a>
     *
     * @param uriInfo The UriInfo object from the JAX-RS context
     * @param code    The code to exchange
     * @return The response from the token endpoint as a JsonNode
     */
    private JsonNode handleCodeTokenExchange(UriInfo uriInfo, String code) {
        String redirectUri = "https://" + uriInfo.getBaseUri().getHost() + "/psamaui/login";
        logger.info(redirectUri);
        String queryString = "grant_type=authorization_code" + "&code=" + code + "&redirect_uri=" + redirectUri;
        String oktaTokenUrl = "https://" + JAXRSConfiguration.idp_provider_uri + "/oauth2/v1/token";
        String contentType = "application/x-www-form-urlencoded; charset=UTF-8";

        return doOktaRequest(oktaTokenUrl, queryString, contentType);
    }

    /**
     * Perform a request to the OKTA API using the provided URL and parameters. The request will be a POST request.
     * It is using Authorization Basic authentication. The client ID and client secret are base64 encoded and sent
     * in the Authorization header.
     *
     * @param requestUrl    The URL to call
     * @param requestParams The parameters to send
     * @param contentType
     * @return The response from the OKTA API as a JsonNode
     */
    private JsonNode doOktaRequest(String requestUrl, String requestParams, String contentType) {
        List<Header> headers = new ArrayList<>();
        Base64.Encoder encoder = Base64.getEncoder();
        String fence_auth_header = JAXRSConfiguration.clientId + ":" + JAXRSConfiguration.spClientSecret;
        headers.add(new BasicHeader("Authorization", "Basic " + encoder.encodeToString(fence_auth_header.getBytes())));
        headers.add(new BasicHeader("Content-type", contentType));

        JsonNode resp = null;
        try {
            resp = HttpClientUtil.simplePost(requestUrl, new StringEntity(requestParams), JAXRSConfiguration.client, JAXRSConfiguration.objectMapper, headers.toArray(new Header[headers.size()]));
        } catch (Exception ex) {
            logger.error("handleCodeTokenExchange() failed to call OKTA token endpoint, " + ex.getMessage());
        }
        logger.debug("getFENCEAccessToken() finished: " + resp.asText());
        return resp;
    }
}
