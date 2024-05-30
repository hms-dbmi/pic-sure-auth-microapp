package edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.harvard.hms.dbmi.avillach.auth.entity.AccessRule;
import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.entity.Connection;
import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.entity.Role;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.exceptions.NotAuthorizedException;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.*;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.authorization.AccessRuleService;
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
import org.springframework.util.CollectionUtils;

import java.io.File;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class FENCEAuthenticationService {

    private final Logger logger = LoggerFactory.getLogger(FENCEAuthenticationService.class);

    private final UserService userService;

    private final RoleService roleService;

    private final ConnectionWebService connectionService; // We will need to investigate if the ConnectionWebService will need to be versioned as well.

    private final AccessRuleService fenceAccessRuleService;

    private final ApplicationService applicationService;

    private final PrivilegeService privilegeService;

    private Application picSureApp;
    private Connection fenceConnection;

    //read the fence_mapping.json into this object to improve lookup speeds
    private static Map<String, Map> _projectMap;

    private static final String parentAccessionField = "\\\\_Parent Study Accession with Subject ID\\\\";
    private static final String topmedAccessionField = "\\\\_Topmed Study Accession with Subject ID\\\\";
    public static final String fence_open_access_role_name = "FENCE_ROLE_OPEN_ACCESS";

    @Value("${fence.harmonized.consent.group.concept.path}")
    private static String fence_harmonized_consent_group_concept_path;

    @Value("${fence.parent.consent.group.concept.path}")
    private static String fence_parent_consent_group_concept_path;

    @Value("${fence.topmed.consent.group.concept.path}")
    private static String fence_topmed_consent_group_concept_path;

    @Value("${fence.harmonized.concept.path}")
    private static String fence_harmonized_concept_path;


    private final Set<String> openAccessIdpValues = Set.of("fence", "ras");

    private static final String[] underscoreFields = new String[] {
            parentAccessionField,
            topmedAccessionField,
            fence_harmonized_consent_group_concept_path,
            fence_parent_consent_group_concept_path,
            fence_topmed_consent_group_concept_path,
            "\\\\_VCF Sample Id\\\\",
            "\\\\_studies\\\\",
            "\\\\_studies_consents\\\\",  //used to provide consent-level counts for open access
            "\\\\_parent_consents\\\\",  //parent consents not used for auth (use combined _consents)
            "\\\\_Consents\\\\"   ///old _Consents\Short Study... path no longer used, but still present in examples.
    };

    private final String idp_provider_uri;
    private final String fence_client_id;
    private final String fence_client_secret;
    private final String idp_provider;
    private final String fence_standard_access_rules;
    private final String fence_allowed_query_types;
    private final String variantAnnotationColumns;
    private final String templatePath;
    private final RestClientUtil restClientUtil;

    @Autowired
    public FENCEAuthenticationService(UserService userService,
                                      RoleService roleService,
                                      ConnectionWebService connectionService,
                                      AccessRuleService fenceAccessRuleService,
                                      ApplicationService applicationService,
                                      PrivilegeService privilegeService,
                                      RestClientUtil restClientUtil,
                                      @Value("${idp.provider.uri}") String idpProviderUri,
                                      @Value("${fence.client.id}") String fenceClientId,
                                      @Value("${fence.client.secret}") String fenceClientSecret,
                                      @Value("${application.idp.provider}") String idpProvider,
                                      @Value("${fence.standard.access.rules}") String fenceStandardAccessRules,
                                      @Value("${fence.allowed.query.types}") String fenceAllowedQueryTypes,
                                      @Value("${fence.variant.annotation.columns}") String variantAnnotationColumns,
                                      @Value("${application.template.path}") String templatePath){
        this.userService = userService;
        this.roleService = roleService;
        this.connectionService = connectionService;
        this.fenceAccessRuleService = fenceAccessRuleService;
        this.applicationService = applicationService;
        this.privilegeService = privilegeService;
        this.idp_provider_uri = idpProviderUri;
        this.fence_client_id = fenceClientId;
        this.fence_client_secret = fenceClientSecret;
        this.idp_provider = idpProvider;
        this.fence_standard_access_rules = fenceStandardAccessRules;
        this.fence_allowed_query_types = fenceAllowedQueryTypes;
        this.variantAnnotationColumns = variantAnnotationColumns;
        this.templatePath = templatePath;
        this.restClientUtil = restClientUtil;
    }

    @PostConstruct
    public void initializeFenceService() {
        picSureApp = applicationService.getApplicationByName("PICSURE");
        fenceConnection = connectionService.getConnectionByLabel("FENCE");
    }

    public HashMap<String, String> getFENCEProfile(String callback_url, Map<String, String> authRequest){
        logger.debug("getFENCEProfile() starting...");
        String fence_code  = authRequest.get("code");

        // Validate that the fence code is alphanumeric
        if (!fence_code.matches("[a-zA-Z0-9]+")) {
            logger.error("getFENCEProfile() fence code is not alphanumeric");
            throw new NotAuthorizedException("The fence code is not alphanumeric");
        }

        JsonNode fence_user_profile = null;
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

        User current_user = null;
        try {
            // Create or retrieve the user profile from our database, based on the the key
            // in the Gen3/FENCE profile
            current_user = createUserFromFENCEProfile(fence_user_profile);
            logger.info("getFENCEProfile() saved details for user with e-mail:"
                    +current_user.getEmail()
                    +" and subject:"
                    +current_user.getSubject());

            // TODO: How do we handle caching now?
            //clear some cache entries if we register a new login
//            AuthorizationService.clearCache(current_user);
//            UserService.clearCache(current_user);

        } catch (Exception ex) {
            logger.error("getFENCEToken() Could not persist the user information, because {}", ex.getMessage());
            throw new NotAuthorizedException("The user details could not be persisted. Please contact the administrator.");
        }

        // Update the user's roles (or create them if none exists)
        Iterator<String> project_access_names = fence_user_profile.get("authz").fieldNames();
        while (project_access_names.hasNext()) {
            String access_role_name = project_access_names.next();
            createAndUpsertRole(access_role_name, current_user);
        }

        final String idp = extractIdp(current_user);

        if (current_user.getRoles() != null && (!current_user.getRoles().isEmpty() || openAccessIdpValues.contains(idp))) {
            Role openAccessRole = roleService.getRoleByName(fence_open_access_role_name);
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



    private void createAndUpsertRole(String access_role_name, User current_user) {
        logger.debug("createAndUpsertRole() starting...");
        Map projectMetadata = getFENCEMapping().values().stream()
                .filter(map -> access_role_name.equals(
                        map.get("authZ").toString().replace("\\/", "/"))
                ).findFirst().orElse(null);

        if (projectMetadata == null) {
            logger.error("getFENCEProfile() -> createAndUpsertRole could not find study in FENCE mapping SKIPPING: {}", access_role_name);
            return;
        }

        String projectId = (String) projectMetadata.get("study_identifier");
        String consentCode = (String) projectMetadata.get("consent_group_code");
        String newRoleName = StringUtils.isNotBlank(consentCode) ? "FENCE_"+projectId+"_"+consentCode : "FENCE_"+projectId;

        logger.info("getFENCEProfile() New PSAMA role name:{}", newRoleName);

        if (upsertRole(current_user, newRoleName, "FENCE role "+newRoleName)) {
            logger.info("getFENCEProfile() Updated user role. Now it includes `{}`", newRoleName);
        } else {
            logger.error("getFENCEProfile() could not add roles to user's profile");
        }
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


    /**
     * Create or update a user record, based on the FENCE user profile, which is in JSON format.
     *
     * @param node User profile, as it is received from Gen3 FENCE, in JSON format
     * @return User The actual entity, as it is persisted (if no errors) in the PSAMA database
     */
    private User createUserFromFENCEProfile(JsonNode node) {
        logger.debug("createUserFromFENCEProfile() starting...");

        User new_user = new User();
        new_user.setSubject("fence|"+node.get("user_id").asText());
        // This is not always an email address, but it is the only attribute other than the sub claim
        // that is guaranteed to be populated by Fence and which makes sense as a display name for a
        // user.
        new_user.setEmail(node.get("username").asText());
        new_user.setGeneralMetadata(node.toString());
        // This is a hack, but someone has to do it.
        new_user.setAcceptedTOS(new Date());
        new_user.setConnection(fenceConnection);
        logger.debug("createUserFromFENCEProfile() finished setting fields");

        User actual_user = userService.findOrCreate(new_user);

        Set<Role> roles = new HashSet<>();
        if (actual_user != null && !CollectionUtils.isEmpty(actual_user.getRoles()))  {
            roles = actual_user.getRoles().stream()
                    .filter(userRole -> "PIC-SURE Top Admin".equals(userRole.getName()) || "Admin".equals(userRole.getName()) || userRole.getName().startsWith("MANUAL_"))
                    .collect(Collectors.toSet());
        }

        // Clear current set of roles every time we create or retrieve a user but persist admin status
        if(actual_user != null){
            actual_user.getRoles().clear();
            actual_user.getRoles().addAll(roles);
        }

        logger.debug("createUserFromFENCEProfile() cleared roles");

        userService.save(actual_user);
        logger.debug("createUserFromFENCEProfile() finished, user record inserted");
        return actual_user;
    }

    /**
     * Insert or Update the User object's list of Roles in the database.
     *
     * @param u The User object the generated Role will be added to
     * @param roleName Name of the Role
     * @param roleDescription Description of the Role
     * @return boolean Whether the Role was successfully added to the User or not
     */
    public boolean upsertRole(User u,  String roleName, String roleDescription) {
        boolean status = false;

        // Get the User's list of Roles. The first time, this will be an empty Set.
        // This method is called for every Role, and the User's list of Roles will
        // be updated for all subsequent calls.
        try {
            Role r = null;
            // Create the Role in the Servicesitory, if it does not exist. Otherwise, add it.
            Role existing_role = roleService.getRoleByName(roleName);
            if (existing_role != null) {
                // Role already exists
                logger.info("upsertRole() role already exists");
                r = existing_role;
            } else {
                // This is a new Role
                r = new Role();
                r.setName(roleName);
                r.setDescription(roleDescription);
                // Since this is a new Role, we need to ensure that the
                // corresponding Privilege (with gates) and AccessRule is added.
                r.setPrivileges(addFENCEPrivileges(u, r));
                roleService.save(r);
                logger.info("upsertRole() created new role");
            }
            if (u != null) {
                u.getRoles().add(r);
            }
            status = true;
        } catch (Exception ex) {
            logger.error("upsertRole() Could not inser/update role {} to Service", roleName, ex);
        }


        logger.debug("upsertRole() finished");
        return status;
    }

    private Set<Privilege> addFENCEPrivileges(User u, Role r) {
        String roleName = r.getName();
        logger.info("addFENCEPrivileges() starting, adding privilege(s) to role {}", roleName);

        //each project can have up to three privileges: Parent  |  Harmonized  | Topmed
        //harmonized has 2 ARs for parent + harminized and harmonized only
        //Topmed has up to three ARs for topmed / topmed + parent / topmed + harmonized
        Set<Privilege> privs = r.getPrivileges();
        if (privs == null) { privs = new HashSet<Privilege>();}

        //e.g. FENCE_phs0000xx_c2 or FENCE_tutorial-biolinc_camp
        String project_name = extractProject(roleName);
        if (project_name.length() <= 0) {
            logger.warn("addFENCEPrivileges() role name: {} returned an empty project name", roleName);
        }
        String consent_group = extractConsentGroup(roleName);
        if (consent_group.length() <= 0) {
            logger.warn("addFENCEPrivileges() role name: {} returned an empty consent group", roleName);
        }
        logger.info("addFENCEPrivileges() project name: {} consent group: {}", project_name, consent_group);

        // Look up the metadata by consent group.
        Map projectMetadata = getFENCEMappingforProjectAndConsent(project_name, consent_group);

        if(projectMetadata == null || projectMetadata.isEmpty()) {
            //no privileges means no access to this project.  just return existing set of privs.
            logger.warn("No metadata available for project {}.{}", project_name, consent_group);
            return privs;
        }

        logger.info("addPrivileges() This is a new privilege");

        String dataType = (String) projectMetadata.get("data_type");
        Boolean isHarmonized = "Y".equals(projectMetadata.get("is_harmonized"));
        String concept_path = (String) projectMetadata.get("top_level_path");
        String projectAlias = (String) projectMetadata.get("abbreviated_name");

        //we need to add escape sequence back in to the path for parsing later (also need to double escape the regex)
        //
        // OK... so, we need to do this for the query Template and scopes, but should NOT do this for the rules.
        //
        // NOTE: I'm leaving this in here for now and removing the escaped values later.  TODO: fix me!
        //
        if(concept_path != null) {
            concept_path = concept_path.replaceAll("\\\\", "\\\\\\\\");
        }

        if(dataType != null && dataType.contains("G")) {
            //insert genomic/topmed privs - this will also add rules for including harmonized & parent data if applicable
            privs.add(upsertTopmedPrivilege(project_name, projectAlias, consent_group, concept_path, isHarmonized));
        }

        if(dataType != null && dataType.contains("P")) {
            //insert clinical privs
            logger.info("addPrivileges() project:{} consent_group:{} concept_path:{}", project_name, consent_group, concept_path);
            privs.add(upsertClinicalPrivilege(project_name, projectAlias, consent_group, concept_path, false));

            //if harmonized study, also create harmonized privileges
            if(Boolean.TRUE.equals(isHarmonized)) {
                privs.add(upsertClinicalPrivilege(project_name, projectAlias, consent_group, concept_path, true));
            }
        }

        //projects without G or P in data_type are skipped
        if(dataType == null || (!dataType.contains("P")  && !dataType.contains("G"))){
            logger.warn("Missing study type for {} {}. Skipping.", project_name, consent_group);
        }

        logger.info("addPrivileges() Finished");
        return privs;
    }

    private static String extractProject(String roleName) {
        String projectPattern = "FENCE_(.*?)(?:_c\\d+)?$";
        if (roleName.startsWith("MANUAL_")) {
            projectPattern = "MANUAL_(.*?)(?:_c\\d+)?$";
        }
        Pattern projectRegex = Pattern.compile(projectPattern);
        Matcher projectMatcher = projectRegex.matcher(roleName);
        String project = "";
        if (projectMatcher.find()) {
            project = projectMatcher.group(1).trim();
        } else {
            String[] parts = roleName.split("_", 1);
            if (parts.length > 0) {
                project = parts[1];
            }
        }
        return project;
    }

    private static String extractConsentGroup(String roleName) {
        String consentPattern = "FENCE_.*?_c(\\d+)$";
        if (roleName.startsWith("MANUAL_")) {
            consentPattern = "MANUAL_.*?_c(\\d+)$";
        }
        Pattern consentRegex = Pattern.compile(consentPattern);
        Matcher consentMatcher = consentRegex.matcher(roleName);
        String consentGroup = "";
        if (consentMatcher.find()) {
            consentGroup = "c" + consentMatcher.group(1).trim();
        }
        return consentGroup;
    }

    /**
     * Creates a privilege with a set of access rules that allow queries containing a consent group to pass if the query only contains valid entries that match conceptPath.  If the study is harmonized,
     * this also creates an access rule to allow access when using the harmonized consent concept path.
     *
     * Privileges created with this method will deny access if any genomic filters (topmed data) are included.
     *
     * @param studyIdentifier the study identifier
     * @param consent_group consent group code
     * @param conceptPath the top level concept path for the study
     * @param isHarmonized whether the study is harmonized
     * @return the created privilege
     */
    private Privilege upsertClinicalPrivilege(String studyIdentifier, String projectAlias, String consent_group, String conceptPath, boolean isHarmonized) {

        String privilegeName = (consent_group != null && consent_group != "") ? "PRIV_FENCE_"+studyIdentifier+"_"+consent_group+(isHarmonized?"_HARMONIZED":"") : "PRIV_FENCE_"+studyIdentifier+(isHarmonized?"_HARMONIZED":"") ;
        Privilege priv = privilegeService.findByName(privilegeName);
        if(priv !=  null) {
            logger.info("upsertClinicalPrivilege() {} already exists", privilegeName);
            return priv;
        }

        priv = new Privilege();

        try {
            priv.setApplication(picSureApp);
            priv.setName(privilegeName);

            String consent_concept_path = isHarmonized ? fence_harmonized_consent_group_concept_path : fence_parent_consent_group_concept_path;

            if(!consent_concept_path.contains("\\\\")){
                //these have to be escaped again so that jaxson can convert it correctly
                consent_concept_path = consent_concept_path.replaceAll("\\\\", "\\\\\\\\");
                logger.debug(consent_concept_path);
            }
            if(fence_harmonized_concept_path != null && !fence_harmonized_concept_path.contains("\\\\")){
                //these have to be escaped again so that jaxson can convert it correctly
                fence_harmonized_concept_path = fence_harmonized_concept_path.replaceAll("\\\\", "\\\\\\\\");
                logger.debug("upsertTopmedPrivilege(): escaped harmonized consent path" + fence_harmonized_concept_path);
            }


            // TOOD: Change this to a mustache template
            String studyIdentifierField = (consent_group != null && consent_group != "") ? studyIdentifier+"."+consent_group: studyIdentifier;
            String queryTemplateText = "{\"categoryFilters\": {\""
                    +consent_concept_path
                    +"\":[\""
                    +studyIdentifierField
                    +"\"]},"
                    +"\"numericFilters\":{},\"requiredFields\":[],";

            if("fence".equalsIgnoreCase(this.idp_provider)) {
                queryTemplateText += "\"fields\":[\"" + parentAccessionField + "\"],";
            } else {
                queryTemplateText += "\"fields\":[],";
            }

            queryTemplateText+="\"variantInfoFilters\":[{\"categoryVariantInfoFilters\":{},\"numericVariantInfoFilters\":{}}],"
                    +"\"expectedResultType\": \"COUNT\""
                    +"}";

            priv.setQueryTemplate(queryTemplateText);
            if(isHarmonized) {
                priv.setQueryScope("[\"" + conceptPath + "\",\"_\",\"" + fence_harmonized_concept_path + "\"]");
            } else {
                priv.setQueryScope("[\"" + conceptPath + "\",\"_\"]");
            }

            Set<AccessRule> accessrules = new HashSet<AccessRule>();

            //just need one AR for parent study
            AccessRule ar = createConsentAccessRule(studyIdentifier, consent_group, "PARENT", fence_parent_consent_group_concept_path);

            //if this is a new rule, we need to populate it
            if(ar.getGates() == null) {
                ar.setGates(new HashSet<AccessRule>());
                ar.getGates().addAll(getGates(true, false, false));

                if(ar.getSubAccessRule() == null) {
                    ar.setSubAccessRule(new HashSet<AccessRule>());
                }
                ar.getSubAccessRule().addAll(getAllowedQueryTypeRules());
                ar.getSubAccessRule().addAll(getPhenotypeSubRules(studyIdentifier, conceptPath, projectAlias));
                ar.getSubAccessRule().addAll(getTopmedRestrictedSubRules());
                fenceAccessRuleService.save(ar);
            }

            accessrules.add(ar);

            // here we add a rule to allow querying a parent study if genomic filters are included.  This goes on all studies;
            // if the study has no genomic data or the user is not authorizzed for genomic studies, there will be 0 patients returned.
            ar = upsertTopmedAccessRule(studyIdentifier, consent_group, "TOPMED+PARENT");

            //if this is a new rule, we need to populate it
            if(ar.getGates() == null) {
                ar.setGates(new HashSet<AccessRule>());
                ar.getGates().addAll(getGates(true, false, true));
                if(ar.getSubAccessRule() == null) {
                    ar.setSubAccessRule(new HashSet<AccessRule>());
                }
                ar.getSubAccessRule().addAll(getAllowedQueryTypeRules());
                ar.getSubAccessRule().addAll(getPhenotypeSubRules(studyIdentifier, conceptPath, projectAlias));
                //this is added in the 'getPhenotypeRestrictedSubRules()' which is not called in this path
                ar.getSubAccessRule().add(createPhenotypeSubRule(fence_topmed_consent_group_concept_path, "ALLOW_TOPMED_CONSENT", "$.query.query.categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "", true));

                fenceAccessRuleService.save(ar);
            }
            accessrules.add(ar);

            if(isHarmonized) {
                //add a rule for accessing only harmonized data
                ar = createConsentAccessRule(studyIdentifier, consent_group, "HARMONIZED", fence_harmonized_consent_group_concept_path);

                //if this is a new rule, we need to populate it
                if(ar.getGates() == null) {
                    ar.setGates(new HashSet<AccessRule>());
                    ar.getGates().add(upsertConsentGate("HARMONIZED_CONSENT", "$.query.query.categoryFilters." + fence_harmonized_consent_group_concept_path + "[*]", true, "harmonized data"));

                    if(ar.getSubAccessRule() == null) {
                        ar.setSubAccessRule(new HashSet<AccessRule>());
                    }
                    ar.getSubAccessRule().addAll(getAllowedQueryTypeRules());
                    ar.getSubAccessRule().addAll(getHarmonizedSubRules());
                    ar.getSubAccessRule().addAll(getPhenotypeSubRules(studyIdentifier, conceptPath, projectAlias));
                    fenceAccessRuleService.save(ar);
                }
                accessrules.add(ar);
            }

            // Add additional access rules;   (these are still created through that SQL script)
            for(String arName: this.fence_standard_access_rules.split(",")) {
                if (arName.startsWith("AR_")) {
                    logger.info("upsertClinicalPrivilege() Adding AccessRule {} to privilege {}", arName, priv.getName());
                    ar = fenceAccessRuleService.getAccessRuleByName(arName);
                    if(ar != null) {
                        accessrules.add(ar);
                    }
                    else {
                        logger.warn("upsertClinicalPrivilege() unable to find an access rule with name {}", arName);
                    }
                }
            }
            priv.setAccessRules(accessrules);
            logger.info("createNewPrivilege() Added {} access_rules to privilege", accessrules.size());

            privilegeService.save(priv);
            logger.info("createNewPrivilege() Added new privilege {} to DB", priv.getName());
        } catch (Exception ex) {
            ex.printStackTrace();
            logger.error("createNewPrivilege() could not save privilege");
        }
        return priv;
    }

    private Set<AccessRule> getAllowedQueryTypeRules() {
        Set<AccessRule> rules = new HashSet<AccessRule>();
        String[] allowedTypes = fence_allowed_query_types.split(",");
        for(String queryType : allowedTypes) {

            String ar_name = "AR_ALLOW_" + queryType ;

            AccessRule ar = fenceAccessRuleService.getAccessRuleByName(ar_name);
            if(ar != null) {
                logger.debug("createTopmedRestrictedSubRule() Found existing rule: {}", ar.getName());
                rules.add(ar);
                continue;
            }

            logger.info("upsertPhenotypeSubRule() Creating new access rule {}", ar_name);
            ar = new AccessRule();
            ar.setName(ar_name);
            ar.setDescription("FENCE SUB AR to allow " + queryType + " Queries");
            ar.setRule( "$.query.query.expectedResultType");
            ar.setType(AccessRule.TypeNaming.ALL_EQUALS);
            ar.setValue(queryType);
            ar.setCheckMapKeyOnly(false);
            ar.setCheckMapNode(false);
            ar.setEvaluateOnlyByGates(false);
            ar.setGateAnyRelation(false);

            fenceAccessRuleService.save(ar);
            rules.add(ar);

        }
        return rules;
    }

    private Collection<? extends AccessRule> getTopmedRestrictedSubRules() {
        Set<AccessRule> rules = new HashSet<AccessRule>();
        rules.add(upsertTopmedRestrictedSubRule("CATEGORICAL", "$.query.query.variantInfoFilters[*].categoryVariantInfoFilters.*"));
        rules.add(upsertTopmedRestrictedSubRule("NUMERIC", "$.query.query.variantInfoFilters[*].numericVariantInfoFilters.*"));

        return rules;
    }

    //topmed restriction rules don't need much configuration.  Just deny all access.
    private AccessRule upsertTopmedRestrictedSubRule(String type, String rule) {
        String ar_name = "AR_TOPMED_RESTRICTED_" + type;

        AccessRule ar = fenceAccessRuleService.getAccessRuleByName(ar_name);
        if(ar != null) {
            logger.debug("createTopmedRestrictedSubRule() Found existing rule: {}", ar.getName());
            return ar;
        }

        logger.info("upsertTopmedRestrictedSubRule() Creating new access rule {}", ar_name);
        ar = new AccessRule();
        ar.setName(ar_name);
        ar.setDescription("FENCE SUB AR for restricting " + type + " genomic concepts");
        ar.setRule(rule);
        ar.setType(AccessRule.TypeNaming.IS_EMPTY);
        ar.setValue(null);
        ar.setCheckMapKeyOnly(false);
        ar.setCheckMapNode(false);
        ar.setEvaluateOnlyByGates(false);
        ar.setGateAnyRelation(false);
        fenceAccessRuleService.save(ar);

        return ar;
    }

    private Collection<? extends AccessRule> getPhenotypeSubRules(String studyIdentifier, String conceptPath, String alias) {

        Set<AccessRule> rules = new HashSet<AccessRule>();
        //categorical filters will always contain at least one entry (for the consent groups); it will never be empty
        rules.add(createPhenotypeSubRule(fence_parent_consent_group_concept_path, "ALLOW_PARENT_CONSENT", "$.query.query.categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "", true));

        for(String underscorePath : underscoreFields) {
            rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$.query.query.fields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "FIELDS", false));
            rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$.query.query.categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "CATEGORICAL", true));
            rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$.query.query.requiredFields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "REQ_FIELDS", false));
        }

        rules.add(createPhenotypeSubRule(conceptPath, alias+ "_" + studyIdentifier, "$.query.query.categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "CATEGORICAL", true));
        rules.add(createPhenotypeSubRule(conceptPath, alias+ "_" + studyIdentifier, "$.query.query.numericFilters", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "NUMERIC", true));
        rules.add(createPhenotypeSubRule(conceptPath, alias+ "_" + studyIdentifier, "$.query.query.fields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "FIELDS", false));
        rules.add(createPhenotypeSubRule(conceptPath, alias+ "_" + studyIdentifier, "$.query.query.requiredFields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "REQUIRED_FIELDS", false));

        return rules;
    }

    /**
     * Harmonized rules should allow the user to supply paretn and top med consent groups;  this allows a single harmonized
     * rules instead of splitting between a topmed+harmonized and parent+harmonized
     *
     * @return
     */
    private Collection<? extends AccessRule> getHarmonizedSubRules() {

        Set<AccessRule> rules = new HashSet<AccessRule>();
        //categorical filters will always contain at least one entry (for the consent groups); it will never be empty
        rules.add(createPhenotypeSubRule(fence_parent_consent_group_concept_path, "ALLOW_PARENT_CONSENT", "$.query.query.categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "", true));
        rules.add(createPhenotypeSubRule(fence_harmonized_consent_group_concept_path, "ALLOW_HARMONIZED_CONSENT", "$.query.query.categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "", true));
        rules.add(createPhenotypeSubRule(fence_topmed_consent_group_concept_path, "ALLOW_TOPMED_CONSENT", "$.query.query.categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "", true));

        for(String underscorePath : underscoreFields ) {
            rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$.query.query.fields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "FIELDS", false));
            rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$.query.query.categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "CATEGORICAL", true));
            rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$.query.query.requiredFields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "REQ_FIELDS", false));
        }

        rules.add(createPhenotypeSubRule(fence_harmonized_concept_path, "HARMONIZED", "$.query.query.categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "CATEGORICAL", true));
        rules.add(createPhenotypeSubRule(fence_harmonized_concept_path, "HARMONIZED", "$.query.query.numericFilters", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "NUMERIC", true));
        rules.add(createPhenotypeSubRule(fence_harmonized_concept_path, "HARMONIZED", "$.query.query.fields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "FIELDS", false));
        rules.add(createPhenotypeSubRule(fence_harmonized_concept_path, "HARMONIZED", "$.query.query.requiredFields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "REQUIRED_FIELDS", false));

        return rules;
    }


    /**
     * generate and return a set of rules that disallow access to phenotype data (only genomic filters allowed)
     * @return
     */
    private Collection<? extends AccessRule> getPhenotypeRestrictedSubRules(String studyIdentifier, String consentCode, String alias) {

        Set<AccessRule> rules = new HashSet<AccessRule>();
        //categorical filters will always contain at least one entry (for the consent groups); it will never be empty
        rules.add(createPhenotypeSubRule(fence_topmed_consent_group_concept_path, "ALLOW_TOPMED_CONSENT", "$.query.query.categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "", true));

        for(String underscorePath : underscoreFields ) {
            rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$.query.query.fields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "FIELDS", false));
            rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$.query.query.categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "CATEGORICAL", true));
            rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$.query.query.requiredFields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "REQ_FIELDS", false));
        }

        rules.add(createPhenotypeSubRule(null, alias + "_" + studyIdentifier+ "_" + consentCode, "$.query.query.numericFilters.[*]", AccessRule.TypeNaming.IS_EMPTY, "DISALLOW_NUMERIC", false));
//    	rules.add(createPhenotypeSubRule(null, alias + "_" + studyIdentifier+ "_" + consentCode, "$.query.query.fields.[*]", AccessRule.TypeNaming.IS_EMPTY, "DISALLOW FIELDS", false, parentRule));
        rules.add(createPhenotypeSubRule(null, alias + "_" + studyIdentifier+ "_" + consentCode, "$.query.query.requiredFields.[*]", AccessRule.TypeNaming.IS_EMPTY, "DISALLOW_REQUIRED_FIELDS", false));

        return rules;
    }

    /**
     * Return a set of gates that identify which consent values have been provided.  the boolean parameters indicate
     * if a value in the specified consent location should allow this gate to pass.
     * @param parent
     * @param harmonized
     * @param topmed
     * @return
     */
    private Collection<? extends AccessRule> getGates(boolean parent, boolean harmonized, boolean topmed) {

        Set<AccessRule> gates = new HashSet<AccessRule>();
        gates.add(upsertConsentGate("PARENT_CONSENT", "$.query.query.categoryFilters." + fence_parent_consent_group_concept_path + "[*]", parent, "parent study data"));
        gates.add(upsertConsentGate("HARMONIZED_CONSENT", "$.query.query.categoryFilters." + fence_harmonized_consent_group_concept_path + "[*]", harmonized, "harmonized data"));
        gates.add(upsertConsentGate("TOPMED_CONSENT", "$.query.query.categoryFilters." + fence_topmed_consent_group_concept_path + "[*]", topmed, "Topmed data"));

        return gates;
    }

    private AccessRule createPhenotypeSubRule(String conceptPath, String alias, String rule, int ruleType, String label, boolean useMapKey) {

        //remove double escape sequence from path evaluation expression
        if(conceptPath != null && conceptPath.contains("\\\\")) {
            //replaceall regex needs to be double escaped (again)
            conceptPath = conceptPath.replaceAll("\\\\\\\\", "\\\\");
        }

        String ar_name = "AR_PHENO_"+alias + "_" + label;

        AccessRule ar = fenceAccessRuleService.getAccessRuleByName(ar_name);
        if(ar != null) {
            logger.debug("createPhenotypeSubRule() Found existing rule: {}", ar.getName());
            return ar;
        }

        logger.info("createPhenotypeSubRule() Creating new access rule {}", ar_name);
        ar = new AccessRule();
        ar.setName(ar_name);
        ar.setDescription("FENCE SUB AR for " + alias + " " + label + " clinical concepts");
        ar.setRule(rule);
        ar.setType(ruleType);
        ar.setValue(ruleType == AccessRule.TypeNaming.IS_NOT_EMPTY ? null : conceptPath);
        ar.setCheckMapKeyOnly(useMapKey);
        ar.setCheckMapNode(useMapKey);
        ar.setEvaluateOnlyByGates(false);
        ar.setGateAnyRelation(false);
        fenceAccessRuleService.save(ar);

        return ar;
    }


    /**
     * Creates a privilege for Topmed access.  This has (up to) three access rules - 1) topmed only 2) topmed + parent 3) topmed+ hermonized  (??)
     * @param studyIdentifier
     * @param consent_group
     * @return
     */
    private Privilege upsertTopmedPrivilege(String studyIdentifier, String projectAlias, String consent_group, String parentConceptPath, boolean isHarmonized) {

        String privilegeName = "PRIV_FENCE_"+studyIdentifier+"_"+consent_group + "_TOPMED";
        Privilege priv = privilegeService.findByName(privilegeName);
        if(priv !=  null) {
            logger.info("upsertTopmedPrivilege() {} already exists", privilegeName);
            return priv;
        }

        priv = new Privilege();


        // Build Privilege Object
        try {
            priv.setApplication(picSureApp);
            priv.setName(privilegeName);
            priv.setDescription("FENCE privilege for Topmed "+studyIdentifier+"."+consent_group);

            String consent_concept_path = fence_topmed_consent_group_concept_path;
            if(!consent_concept_path.contains("\\\\")){
                //these have to be escaped again so that jaxson can convert it correctly
                consent_concept_path = consent_concept_path.replaceAll("\\\\", "\\\\\\\\");
                logger.debug("upsertTopmedPrivilege(): escaped parent consent path{}", consent_concept_path);
            }

            if(fence_harmonized_concept_path != null && !fence_harmonized_concept_path.contains("\\\\")){
                //these have to be escaped again so that jaxson can convert it correctly
                fence_harmonized_concept_path = fence_harmonized_concept_path.replaceAll("\\\\", "\\\\\\\\");
                logger.debug("upsertTopmedPrivilege(): escaped harmonized consent path{}", fence_harmonized_concept_path);
            }

            String queryTemplateText = "{\"categoryFilters\": {\""
                    +consent_concept_path
                    +"\":[\""
                    +studyIdentifier+"."+consent_group
                    +"\"]},"
                    +"\"numericFilters\":{},\"requiredFields\":[],"
                    +"\"fields\":[\"" + topmedAccessionField + "\"],"
                    +"\"variantInfoFilters\":[{\"categoryVariantInfoFilters\":{},\"numericVariantInfoFilters\":{}}],"
                    +"\"expectedResultType\": \"COUNT\""
                    +"}";
            priv.setQueryTemplate(queryTemplateText);
            //need a non-null scope that is a list of strings



            String variantColumns = this.variantAnnotationColumns;
            if(variantColumns == null || variantColumns.isEmpty()) {
                priv.setQueryScope("[\"_\"]");
            } else {
                StringBuilder builder = new StringBuilder();
                for(String annotationPath : variantColumns.split(",")) {
                    if(builder.length() == 0) {
                        builder.append("[");
                    } else {
                        builder.append(",");
                    }
                    builder.append("\""+annotationPath+"\"");
                }
                builder.append(",\"_\"");
                builder.append("]");
                priv.setQueryScope(builder.toString());
            }


            Set<AccessRule> accessrules = new HashSet<AccessRule>();

            AccessRule ar = upsertTopmedAccessRule(studyIdentifier, consent_group, "TOPMED");

            //if this is a new rule, we need to populate it
            if(ar.getGates() == null) {
                ar.setGates(new HashSet<AccessRule>());
                ar.getGates().addAll(getGates(false, false, true));

                if(ar.getSubAccessRule() == null) {
                    ar.setSubAccessRule(new HashSet<AccessRule>());
                }
                ar.getSubAccessRule().addAll(getAllowedQueryTypeRules());
                ar.getSubAccessRule().addAll(getPhenotypeRestrictedSubRules(studyIdentifier, consent_group, projectAlias));
                fenceAccessRuleService.save(ar);
            }
            accessrules.add(ar);

            if(parentConceptPath != null) {

                ar = upsertTopmedAccessRule(studyIdentifier, consent_group, "TOPMED+PARENT");

                //if this is a new rule, we need to populate it
                if(ar.getGates() == null) {
                    ar.setGates(new HashSet<AccessRule>());
                    ar.getGates().addAll(getGates(true, false, true));
                    if(ar.getSubAccessRule() == null) {
                        ar.setSubAccessRule(new HashSet<AccessRule>());
                    }
                    ar.getSubAccessRule().addAll(getAllowedQueryTypeRules());
                    ar.getSubAccessRule().addAll(getPhenotypeSubRules(studyIdentifier, parentConceptPath, projectAlias));
                    //this is added in the 'getPhenotypeRestrictedSubRules()' which is not called in this path
                    ar.getSubAccessRule().add(createPhenotypeSubRule(fence_topmed_consent_group_concept_path, "ALLOW_TOPMED_CONSENT", "$.query.query.categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "", true));

                    fenceAccessRuleService.save(ar);
                }
                accessrules.add(ar);


                if(isHarmonized) {
                    ar = upsertHarmonizedAccessRule(studyIdentifier, consent_group, "HARMONIZED");

                    //if this is a new rule, we need to populate it
                    if(ar.getGates() == null) {
                        ar.setGates(new HashSet<AccessRule>());
//                      	ar.getGates().addAll(getGates(true, true, false));
                        ar.getGates().add(upsertConsentGate("HARMONIZED_CONSENT", "$.query.query.categoryFilters." + fence_harmonized_consent_group_concept_path + "[*]", true, "harmonized data"));

                        if(ar.getSubAccessRule() == null) {
                            ar.setSubAccessRule(new HashSet<AccessRule>());
                        }
                        ar.getSubAccessRule().addAll(getAllowedQueryTypeRules());
                        ar.getSubAccessRule().addAll(getHarmonizedSubRules());
                        ar.getSubAccessRule().addAll(getPhenotypeSubRules(studyIdentifier, parentConceptPath, projectAlias));
                        fenceAccessRuleService.save(ar);
                    }
                    accessrules.add(ar);
                }

            }

            // Add additional access rules;
            for(String arName: fence_standard_access_rules.split(",")) {
                if (arName.startsWith("AR_")) {
                    logger.info("upsertTopmedPrivilege() Adding AccessRule {} to privilege {}", arName, priv.getName());
                    ar = fenceAccessRuleService.getAccessRuleByName(arName);
                    if(ar != null) {
                        accessrules.add(ar);
                    }
                    else {
                        logger.warn("uupsertTopmedPrivilege() nable to find an access rule with name {}", arName);
                    }
                }
            }
            priv.setAccessRules(accessrules);
            logger.info("upsertTopmedPrivilege() Added {} access_rules to privilege", accessrules.size());

            privilegeService.save(priv);
            logger.info("upsertTopmedPrivilege() Added new privilege {} to DB", priv.getName());
        } catch (Exception ex) {
            logger.error("upsertTopmedPrivilege() could not save privilege", ex);
        }
        return priv;
    }

    //Generates Main rule only; gates & sub rules attached after calling this
    // prentRule should be null if this is the main rule, or the appropriate value if this is a sub rule
    private AccessRule createConsentAccessRule(String studyIdentifier, String consent_group, String label, String consent_path) {
        logger.debug("upsertConsentAccessRule() starting");
        String ar_name = (consent_group != null && !consent_group.isEmpty()) ? "AR_CONSENT_" + studyIdentifier+"_"+consent_group+ "_" +label : "AR_CONSENT_" + studyIdentifier;

        AccessRule ar = fenceAccessRuleService.getAccessRuleByName(ar_name);
        if(ar != null) {
            logger.debug("upsertConsentAccessRule() Found existing rule: {}", ar.getName());
            return ar;
        }


        logger.info("upsertConsentAccessRule() Creating new access rule {}", ar_name);
        ar = new AccessRule();
        ar.setName(ar_name);
        String description = (consent_group != null && !consent_group.isEmpty()) ? "FENCE AR for "+studyIdentifier+"."+consent_group + " clinical concepts" : "FENCE AR for "+studyIdentifier+" clinical concepts";
        ar.setDescription(description);
        StringBuilder ruleText = new StringBuilder();
        ruleText.append("$.query.query.categoryFilters.");
        ruleText.append(consent_path);
        ruleText.append("[*]");
        ar.setRule(ruleText.toString());
        ar.setType(AccessRule.TypeNaming.ALL_CONTAINS);
        String arValue = (consent_group != null && consent_group != "") ? studyIdentifier+"."+consent_group : studyIdentifier;
        ar.setValue(arValue);
        ar.setCheckMapKeyOnly(false);
        ar.setCheckMapNode(false);
        ar.setEvaluateOnlyByGates(false);
        ar.setGateAnyRelation(false);

        fenceAccessRuleService.save(ar);

        logger.debug("upsertConsentAccessRule() finished");
        return ar;
    }

    // Generates Main Rule only; gates & sub rules attached by calling method
    private AccessRule upsertTopmedAccessRule(String project_name, String consent_group, String label ) {
        logger.debug("upsertTopmedAccessRule() starting");
        String ar_name = (consent_group != null && !consent_group.isEmpty()) ? "AR_TOPMED_"+project_name+"_"+consent_group + "_" + label : "AR_TOPMED_"+project_name+"_"+label;
        AccessRule ar = fenceAccessRuleService.getAccessRuleByName(ar_name);
        if (ar != null) {
            logger.info("upsertTopmedAccessRule() AccessRule {} already exists.", ar_name);
            return ar;
        }

        logger.info("upsertTopmedAccessRule() Creating new access rule {}", ar_name);
        ar = new AccessRule();
        ar.setName(ar_name);
        ar.setDescription("FENCE AR for "+project_name+"."+consent_group + " Topmed data");
        StringBuilder ruleText = new StringBuilder();
        ruleText.append("$.query.query.categoryFilters.");
        ruleText.append(fence_topmed_consent_group_concept_path);
        ruleText.append("[*]");
        ar.setRule(ruleText.toString());
        ar.setType(AccessRule.TypeNaming.ALL_CONTAINS);
        String arValue = (consent_group != null && !consent_group.isEmpty()) ? project_name+"."+consent_group : project_name;
        ar.setValue(arValue);
        ar.setCheckMapKeyOnly(false);
        ar.setCheckMapNode(false);
        ar.setEvaluateOnlyByGates(false);
        ar.setGateAnyRelation(false);

        fenceAccessRuleService.save(ar);

        logger.debug("upsertTopmedAccessRule() finished");
        return ar;
    }


    // Generates Main Rule only; gates & sub rules attached by calling method
    private AccessRule upsertHarmonizedAccessRule(String project_name, String consent_group, String label ) {
        logger.debug("upsertTopmedAccessRule() starting");
        String ar_name = "AR_TOPMED_"+project_name+"_"+consent_group + "_" + label;
        AccessRule ar = fenceAccessRuleService.getAccessRuleByName(ar_name);
        if (ar != null) {
            logger.info("upsertTopmedAccessRule() AccessRule {} already exists.", ar_name);
            return ar;
        }

        logger.info("upsertTopmedAccessRule() Creating new access rule {}", ar_name);
        ar = new AccessRule();
        ar.setName(ar_name);
        ar.setDescription("FENCE AR for "+project_name+"."+consent_group + " Topmed data");
        StringBuilder ruleText = new StringBuilder();
        ruleText.append("$.query.query.categoryFilters.");
        ruleText.append(fence_harmonized_consent_group_concept_path);
        ruleText.append("[*]");
        ar.setRule(ruleText.toString());
        ar.setType(AccessRule.TypeNaming.ALL_CONTAINS);
        ar.setValue(project_name+"."+consent_group);
        ar.setCheckMapKeyOnly(false);
        ar.setCheckMapNode(false);
        ar.setEvaluateOnlyByGates(false);
        ar.setGateAnyRelation(false);

        fenceAccessRuleService.save(ar);

        logger.debug("upsertTopmedAccessRule() finished");
        return ar;
    }

    /**
     * Insert a new gate (if it doesn't exist yet) to identify if consent values are present in the query.
     * return an existing gate named GATE_{gateName}_(PRESENT|MISSING) if it exists.
     */
    private AccessRule upsertConsentGate(String gateName, String rule, boolean is_present, String description) {

        gateName = "GATE_" + gateName + "_" + (is_present ? "PRESENT": "MISSING");

        AccessRule gate = fenceAccessRuleService.getAccessRuleByName(gateName);
        if (gate != null) {
            logger.info("upsertConsentGate() AccessRule {} already exists.", gateName);
            return gate;
        }

        logger.info("upsertClinicalGate() Creating new access rule {}", gateName);
        gate = new AccessRule();
        gate.setName(gateName);
        gate.setDescription("FENCE GATE for " + description + " consent " + (is_present ? "present" : "missing"));
        gate.setRule(rule);
        gate.setType(is_present ? AccessRule.TypeNaming.IS_NOT_EMPTY : AccessRule.TypeNaming.IS_EMPTY );
        gate.setValue(null);
        gate.setCheckMapKeyOnly(false);
        gate.setCheckMapNode(false);
        gate.setEvaluateOnlyByGates(false);
        gate.setGateAnyRelation(false);

        fenceAccessRuleService.save(gate);
        return gate;
    }

    private Map getFENCEMappingforProjectAndConsent(String projectId, String consent_group) {

        String consentVal = (consent_group != null && consent_group != "") ? projectId + "." + consent_group : projectId;
        logger.info("getFENCEMappingforProjectAndConsent() looking up {}", consentVal);

        Object projectMetadata = getFENCEMapping().get(consentVal);
        if( projectMetadata instanceof Map) {
            return (Map)projectMetadata;
        } else if (projectMetadata != null) {
            logger.info("getFENCEMappingforProjectAndConsent() Obj instance of " + projectMetadata.getClass().getCanonicalName());
        }
        return null;
    }

    public Map<String, Map> getFENCEMapping(){
        if(_projectMap == null || _projectMap.isEmpty()) {
            ObjectMapper mapper = new ObjectMapper();

            try {
                Map fenceMapping = mapper.readValue(
                        new File(String.join(File.separator,
                                new String[] {this.templatePath ,"fence_mapping.json"}))
                        , Map.class);
                List<Map> projects = (List<Map>) fenceMapping.get("bio_data_catalyst");
                logger.debug("getFENCEMapping: found FENCE mapping with {} entries", projects.size());
                _projectMap = new HashMap<String, Map>(projects.size());
                for(Map project : projects) {
                    String consentVal = (project.get("consent_group_code") != null && project.get("consent_group_code") != "") ?
                            "" + project.get("study_identifier") + "." + project.get("consent_group_code") :
                            "" + project.get("study_identifier");
                    logger.debug("adding study {}", consentVal);
                    _projectMap.put(consentVal, project);
                }

            } catch (Exception e) {
                logger.error("getFENCEMapping: Non-fatal error parsing fence_mapping.json: {}", this.templatePath, e);
                return new HashMap<>();
            }
        }

        return _projectMap;
    }

}
