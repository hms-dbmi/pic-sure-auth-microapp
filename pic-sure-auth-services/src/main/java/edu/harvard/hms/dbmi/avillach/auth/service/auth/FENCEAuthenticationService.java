package edu.harvard.hms.dbmi.avillach.auth.service.auth;

import com.fasterxml.jackson.databind.JsonNode;
import edu.harvard.dbmi.avillach.util.HttpClientUtil;
import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.RoleRepository;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.UserRepository;
import edu.harvard.hms.dbmi.avillach.auth.rest.UserService;
import edu.harvard.hms.dbmi.avillach.auth.service.MailService;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthUtils;
import org.apache.http.Header;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.Response;
import java.util.*;

public class FENCEAuthenticationService {
    private Logger logger = LoggerFactory.getLogger(FENCEAuthenticationService.class);

    @Inject
    UserRepository userRepository;

    @Inject
    RoleRepository roleRepo;

    @Inject
    MailService mailService;

    @Inject
    UserService userService;

    @Inject
    AuthUtils authUtil;

    private JsonNode getFENCEUserProfile(String access_token) {
        logger.debug("getFENCEUserProfile() starting");
        List<Header> headers = new ArrayList<>();
        headers.add(new BasicHeader("Authorization", "Bearer " + access_token));

        logger.debug("getFENCEUserProfile() getting user profile from uri:"+JAXRSConfiguration.idp_provider_uri+"/user/user");
        JsonNode fence_user_profile_response = HttpClientUtil.simpleGet(
                JAXRSConfiguration.idp_provider_uri+"/user/user",
                JAXRSConfiguration.client,
                JAXRSConfiguration.objectMapper,
                headers.toArray(new Header[headers.size()])
        );

        logger.debug("getFENCEUserProfile() finished, returning user profile"+fence_user_profile_response.asText());
        return fence_user_profile_response;
    }

    private JsonNode getFENCEAccessToken(String fence_code) {
        logger.debug("getFENCEAccessToken() starting, using FENCE code");

        List<Header> headers = new ArrayList<>();
        Base64.Encoder encoder = Base64.getEncoder();
        String fence_auth_header = JAXRSConfiguration.fence_client_id+":"+JAXRSConfiguration.fence_client_secret;
        headers.add(new BasicHeader("Authorization",
                "Basic " + encoder.encodeToString(fence_auth_header.getBytes())));
        headers.add(new BasicHeader("Content-type", "application/x-www-form-urlencoded; charset=UTF-8"));

        // Build the request body, as JSON
        StringBuilder query_string = new StringBuilder()
                .append("grant_type").append('=').append("authorization_code").append('&')
                .append("code").append('=').append(fence_code).append('&')
                .append("redirect_uri").append('=').append(JAXRSConfiguration.fence_redirect_url);

        String fence_token_url = JAXRSConfiguration.idp_provider_uri+"/user/oauth2/token";

        JsonNode resp = null;
        try {
            resp = HttpClientUtil.simplePost(
                    fence_token_url,
                    new StringEntity(query_string.toString()),
                    JAXRSConfiguration.client,
                    JAXRSConfiguration.objectMapper,
                    headers.toArray(new Header[headers.size()])
            );
        } catch (Exception ex) {
            logger.error("getFENCEAccessToken() failed to call FENCE token service, "+ex.getMessage());
        }
        logger.debug("getFENCEAccessToken() finished. "+resp.asText());
        return resp;
    }

    // Get access_token from FENCE, based on the provided `code`
    public Response getFENCEProfile(Map<String, String> authRequest){
        logger.debug("getFENCEProfile() starting...");
        String fence_code  = authRequest.get("code");

        JsonNode fence_user_profile = null;
        // Get the Gen3/FENCE user profile. It is a JsonNode object
        try {
            logger.debug("getFENCEProfile() query FENCE for user profile with code");
            fence_user_profile = getFENCEUserProfile(getFENCEAccessToken(fence_code).get("access_token").asText());
            logger.debug("getFENCEProfile() user profile structure:"+fence_user_profile.asText());
            logger.debug("getFENCEProfile() .username:" + fence_user_profile.get("username"));
            logger.debug("getFENCEProfile() .user_id:" + fence_user_profile.get("user_id"));
            logger.debug("getFENCEProfile() .email:" + fence_user_profile.get("email"));
        } catch (Exception ex) {
            logger.error("getFENCEToken() could not retrieve the user profile from the auth provider, because "+ex.getMessage());
            throw new NotAuthorizedException("Could not get the user profile "+
                    "from the Gen3 authentication provider."+ex.getMessage());
        }

        User current_user = null;
        try {
            // Create or retrieve the user profile from our database, based on the the key
            // in the Gen3/FENCE profile
            current_user = userService.createUserFromFENCEProfile(fence_user_profile);
            logger.info("getFENCEProfile() saved details for user with e-mail:"
                    +current_user.getEmail()
                    +" and subject:"
                    +current_user.getSubject());

        } catch (Exception ex) {
            logger.error("getFENCEToken() Could not persist the user information, because "+ex.getMessage());
            throw new NotAuthorizedException("The user details could not be persisted. Please contact the administrator.");
        }

        // Update the user's roles (or create them if none exists)
        //Set<Role> actual_user_roles = u.getRoles();
        Iterator<String> access_role_names = fence_user_profile.get("project_access").fieldNames();
        while (access_role_names.hasNext()) {
            String access_role_name = access_role_names.next();

            logger.debug("getFENCEProfile() AccessRole:"+access_role_name);
            String[] parts = access_role_name.split("\\.");
            String newRoleName = "FENCE_"+parts[0]+"_"+parts[3];
            logger.info("getFENCEProfile() New PSAMA role name:"+newRoleName);

                if (userService.upsertRole(current_user, newRoleName, "FENCE role "+newRoleName)) {
                    logger.info("getFENCEProfile() Updated user role. Now it includes `"+newRoleName+"`");
                } else {
                    logger.error("getFENCEProfile() could not add roles to user's profile");
                }

                // TODO: In case we need to do something with this part, we can uncomment it.
                //JsonNode role_object = fence_user_profile.get("project_access").get(newRoleName);
                //It is a an array of strings, like this: ["read-storage","read"]
                //logger.debug("getFENCEProfile() object:"+role_object.toString());
        }

        HashMap<String, Object> claims = new HashMap<String,Object>();
        claims.put("name", fence_user_profile.get("name"));
        claims.put("email", current_user.getEmail());
        claims.put("sub", current_user.getSubject());
        HashMap<String, String> responseMap = authUtil.getUserProfileResponse(claims);
        logger.debug("getFENCEProfile() UserProfile response object has been generated");

        logger.debug("getFENCEToken() finished");
        return PICSUREResponse.success(responseMap);
    }
}
