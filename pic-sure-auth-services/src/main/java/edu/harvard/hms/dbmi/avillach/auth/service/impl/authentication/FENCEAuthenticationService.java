package edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.harvard.hms.dbmi.avillach.auth.entity.Connection;
import edu.harvard.hms.dbmi.avillach.auth.entity.Role;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.exceptions.NotAuthorizedException;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.*;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.authorization.AccessRuleService;
import edu.harvard.hms.dbmi.avillach.auth.utils.FenceMappingUtility;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import jakarta.annotation.PostConstruct;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class FENCEAuthenticationService {

    private final Logger logger = LoggerFactory.getLogger(FENCEAuthenticationService.class);

    private final UserService userService;
    private final RoleService roleService;
    private final ConnectionWebService connectionService;
    private final AccessRuleService accessRuleService;
    private final FenceMappingUtility fenceMappingUtility;

    private Connection fenceConnection;

    private final Set<String> openAccessIdpValues = Set.of("fence", "ras");

    private final String idp_provider_uri;
    private final String fence_client_id;
    private final String fence_client_secret;

    public static final String fence_open_access_role_name = "FENCE_ROLE_OPEN_ACCESS";
    private final RestClientUtil restClientUtil;

    @Autowired
    public FENCEAuthenticationService(UserService userService,
                                      RoleService roleService,
                                      ConnectionWebService connectionService,
                                      RestClientUtil restClientUtil,
                                      AccessRuleService accessRuleService,
                                      FenceMappingUtility fenceMappingUtility,
                                      @Value("${application.idp.provider.uri}") String idpProviderUri,
                                      @Value("${fence.client.id}") String fenceClientId,
                                      @Value("${fence.client.secret}") String fenceClientSecret){
        this.userService = userService;
        this.roleService = roleService;
        this.connectionService = connectionService;
        this.idp_provider_uri = idpProviderUri;
        this.fence_client_id = fenceClientId;
        this.fence_client_secret = fenceClientSecret;
        this.restClientUtil = restClientUtil;
        this.accessRuleService = accessRuleService;
        this.fenceMappingUtility = fenceMappingUtility;
    }

    @PostConstruct
    public void initializeFenceService() {
        fenceConnection = connectionService.getConnectionByLabel("FENCE");

        logger.info("idp_provider_uri: {}", idp_provider_uri);
        logger.info("fence_client_id: {}", fence_client_id);
        logger.info("fence_client_secret: {}", fence_client_secret);
    }

    public HashMap<String, String> getFENCEProfile(String callback_url, Map<String, String> authRequest){
        logger.debug("getFENCEProfile() starting...");
        String fence_code  = authRequest.get("code");

        // Validate that the fence code is alphanumeric
        if (!fence_code.matches("[a-zA-Z0-9]+")) {
            logger.error("getFENCEProfile() fence code is not alphanumeric");
            throw new NotAuthorizedException("The fence code is not alphanumeric");
        }

        JsonNode fence_user_profile;
        // Get the Gen3/FENCE user profile. It is a JsonNode object
        try {
            logger.debug("getFENCEProfile() query FENCE for user profile with code");
            fence_user_profile = getFENCEUserProfile(getFENCEAccessToken(callback_url, fence_code).get("access_token").asText());

            if(logger.isTraceEnabled()){
                // create object mapper instance
                ObjectMapper mapper = new ObjectMapper();
                // `JsonNode` to JSON string
                String prettyString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(fence_user_profile);

                logger.trace("getFENCEProfile() user profile structure:{}", prettyString);
            }
            logger.debug("getFENCEProfile() .username:{}", fence_user_profile.get("username"));
            logger.debug("getFENCEProfile() .user_id:{}", fence_user_profile.get("user_id"));
            logger.debug("getFENCEProfile() .email:{}", fence_user_profile.get("email"));
        } catch (Exception ex) {
            logger.error("getFENCEProfile() could not retrieve the user profile from the auth provider, because {}", ex.getMessage(), ex);
            throw new NotAuthorizedException("Could not get the user profile "+
                    "from the Gen3 authentication provider."+ex.getMessage());
        }

        User current_user;
        try {
            // Create or retrieve the user profile from our database, based on the the key
            // in the Gen3/FENCE profile
            current_user = this.userService.createUserFromFENCEProfile(fence_user_profile, fenceConnection);
            logger.info("getFENCEProfile() saved details for user with e-mail:{} and subject:{}", current_user.getEmail(), current_user.getSubject());

            accessRuleService.evictFromCache(current_user);
            userService.evictFromCache(current_user);
        } catch (Exception ex) {
            logger.error("getFENCEToken() Could not persist the user information, because {}", ex.getMessage());
            throw new NotAuthorizedException("The user details could not be persisted. Please contact the administrator.");
        }

        updateUserRoles(fence_user_profile, current_user);

        final String idp = extractIdp(current_user);
        if (current_user.getRoles() != null && (!current_user.getRoles().isEmpty() || openAccessIdpValues.contains(idp))) {
            Role openAccessRole = roleService.findByName(fence_open_access_role_name);
            if (openAccessRole != null) {
                current_user.getRoles().add(openAccessRole);
            } else {
                logger.warn("Unable to find fence OPEN ACCESS role");
            }
        }

        try {
            userService.changeRole(current_user, current_user.getRoles());
            logger.debug("upsertRole() updated user, who now has {} roles.", current_user.getRoles().size());
        } catch (Exception ex) {
            logger.error("upsertRole() Could not add roles to user, because {}", ex.getMessage());
        }
        HashMap<String, Object> claims = new HashMap<String,Object>();
        claims.put("name", fence_user_profile.get("name"));
        claims.put("email", current_user.getEmail());
        claims.put("sub", current_user.getSubject());
        HashMap<String, String> responseMap = userService.getUserProfileResponse(claims);
        logger.info("LOGIN SUCCESS ___ {}:{}:{} ___ Authorization will expire at  ___ {}___", current_user.getEmail(), current_user.getUuid().toString(), current_user.getSubject(), responseMap.get("expirationDate"));
        logger.debug("getFENCEProfile() UserProfile response object has been generated");
        logger.debug("getFENCEToken() finished");

        return responseMap;
    }

    private void updateUserRoles(JsonNode fence_user_profile, User current_user) {
        // Update the user's roles (or create them if none exists)
        //Set<Role> actual_user_roles = u.getRoles();
        Iterator<String> project_access_names = fence_user_profile.get("authz").fieldNames();

        // I want to parallelize this, but I'm not sure if it's safe to do so.
        Set<String> roleNames = new HashSet<>();
        project_access_names.forEachRemaining(roleName -> {
            // We need to add/remove the users roles based on what is in the project_access_names list
            Map projectMetadata = this.fenceMappingUtility.getFenceMappingByAuthZ().get(roleName);
            if (projectMetadata == null) {
                logger.error("getFENCEProfile() -> createAndUpsertRole could not find study in FENCE mapping SKIPPING: {}", roleName);
                return;
            }

            String projectId = (String) projectMetadata.get("study_identifier");
            String consentCode = (String) projectMetadata.get("consent_group_code");
            String newRoleName = StringUtils.isNotBlank(consentCode) ? "FENCE_"+projectId+"_"+consentCode : "FENCE_"+projectId;

            roleNames.add(newRoleName);
        });

        // find roles that are in the user's roles but not in the project_access_names. These are the roles that need to be removed.
        // exclude userRole -> "PIC-SURE Top Admin".equals(userRole.getName()) || "Admin".equals(userRole.getName()) || userRole.getName().startsWith("MANUAL_")
        Set<Role> rolesToRemove = current_user.getRoles().parallelStream()
                .filter(role -> !roleNames.contains(role.getName()) && !role.getName().equals(fence_open_access_role_name) && !role.getName().startsWith("MANUAL_") && !role.getName().equals("PIC-SURE Top Admin") && !role.getName().equals("Admin"))
                .collect(Collectors.toSet());

        if (!rolesToRemove.isEmpty()) {
            current_user.getRoles().removeAll(rolesToRemove);
            logger.debug("upsertRole() removed {} roles from user", rolesToRemove.size());
            logger.debug("User roles after removal: {}", current_user.getRoles().size());
        }

        // find roles that are in the project_access_names but not in the user's roles. These are the roles that need to be added.
        List<Role> newRoles = roleNames.parallelStream()
                .map(roleName -> roleService.createRole(roleName, "FENCE role " + roleName))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        if (!newRoles.isEmpty()) {
            roleService.persistAll(newRoles);
            current_user.getRoles().addAll(newRoles);
        }
    }

    private JsonNode getFENCEUserProfile(String access_token) {
        logger.debug("getFENCEUserProfile() starting");

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(access_token);

        logger.debug("getFENCEUserProfile() getting user profile from uri:{}/user/user", this.idp_provider_uri);
        ResponseEntity<String> fence_user_profile_response = this.restClientUtil.retrieveGetResponse(
                this.idp_provider_uri+"/user/user",
                headers
        );

        // Map the response to a JsonNode object
        JsonNode fence_user_profile_response_json = null;
        try {
            ObjectMapper mapper = new ObjectMapper();
            fence_user_profile_response_json = mapper.readTree(fence_user_profile_response.getBody());
        } catch (JsonProcessingException e) {
            logger.error("getFENCEUserProfile() failed to parse the user profile response from FENCE, {}", e.getMessage());
        }

        logger.debug("getFENCEUserProfile() finished, returning user profile{}", fence_user_profile_response_json != null ? fence_user_profile_response_json.asText() : null);
        return fence_user_profile_response_json;
    }

    private JsonNode getFENCEAccessToken(String callback_url, String fence_code) {
        logger.debug("getFENCEAccessToken() starting, using FENCE code");

        HttpHeaders headers = new HttpHeaders();
        Base64.Encoder encoder = Base64.getEncoder();
        String fence_auth_header = this.fence_client_id+":"+this.fence_client_secret;
        String encodedAuth = encoder.encodeToString(fence_auth_header.getBytes());
        headers.setBearerAuth(encodedAuth);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        // Build the request body, as JSON
        String query_string =
                "grant_type=authorization_code"
                        + "&code=" + fence_code
                        + "&redirect_uri=" + callback_url;

        String fence_token_url = this.idp_provider_uri+"/user/oauth2/token";

        JsonNode respJson = null;
        ResponseEntity<String> resp = null;
        try {
            resp = RestClientUtil.retrievePostResponseWithParams(
                    fence_token_url,
                    headers,
                    query_string
            );

            respJson = new ObjectMapper().readTree(resp.getBody());
        } catch (Exception ex) {
            logger.error("getFENCEAccessToken() failed to call FENCE token service, {}", ex.getMessage());
        }

        logger.debug("getFENCEAccessToken() finished: {}", respJson.asText());
        return respJson;
    }

    private String extractIdp(User current_user) {
        try {
            final ObjectNode node;
            node = new ObjectMapper().readValue(current_user.getGeneralMetadata(), ObjectNode.class);
            return node.get("idp").asText();
        } catch (JsonProcessingException e) {
            logger.warn("Error parsing idp value from medatada", e);
            return "";
        }
    }

}
