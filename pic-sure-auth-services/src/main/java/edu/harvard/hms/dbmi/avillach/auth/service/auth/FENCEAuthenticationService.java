package edu.harvard.hms.dbmi.avillach.auth.service.auth;

import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_harmonized_concept_path;
import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_harmonized_consent_group_concept_path;
import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_parent_consent_group_concept_path;
import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_standard_access_rules;
import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_topmed_consent_group_concept_path;
import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_no_access_role_name;
import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_open_access_role_name;

import java.io.File;
import java.util.*;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.Response;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.Header;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import edu.harvard.dbmi.avillach.util.HttpClientUtil;
import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.*;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.*;
import edu.harvard.hms.dbmi.avillach.auth.rest.UserService;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthUtils;

public class FENCEAuthenticationService {
	private Logger logger = LoggerFactory.getLogger(FENCEAuthenticationService.class);

    @Inject
    UserRepository userRepo;

    @Inject
    RoleRepository roleRepo;

    @Inject
    ConnectionRepository connectionRepo;

    @Inject
    AccessRuleRepository accessruleRepo;

    @Inject
    UserRepository userRole;

    @Inject
    ApplicationRepository applicationRepo;

    @Inject
    PrivilegeRepository privilegeRepo;

    @Inject
    AuthUtils authUtil;

    private Application picSureApp;
    private Connection fenceConnection;
    
    //read the fence_mapping.json into this object to improve lookup speeds
    private static Map<String, Map> _projectMap;
    
    private static final String parentAccessionField = "\\\\_Parent Study Accession with Subject ID\\\\";
    private static final String topmedAccessionField = "\\\\_Topmed Study Accession with Subject ID\\\\";

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

    @PostConstruct
	public void initializeFenceService() {
		 picSureApp = applicationRepo.getUniqueResultByColumn("name", "PICSURE");
		 fenceConnection = connectionRepo.getUniqueResultByColumn("label", "FENCE");
    }

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

    private JsonNode getFENCEAccessToken(String callback_url, String fence_code) {
        logger.debug("getFENCEAccessToken() starting, using FENCE code");

        List<Header> headers = new ArrayList<>();
        Base64.Encoder encoder = Base64.getEncoder();
        String fence_auth_header = JAXRSConfiguration.fence_client_id+":"+JAXRSConfiguration.fence_client_secret;
        headers.add(new BasicHeader("Authorization",
                "Basic " + encoder.encodeToString(fence_auth_header.getBytes())));
        headers.add(new BasicHeader("Content-type", "application/x-www-form-urlencoded; charset=UTF-8"));

        // Build the request body, as JSON
		String query_string =
        		"grant_type=authorization_code"
        				+ "&code=" + fence_code
        				+ "&redirect_uri=" + callback_url;

        String fence_token_url = JAXRSConfiguration.idp_provider_uri+"/user/oauth2/token";

        JsonNode resp = null;
        try {
            resp = HttpClientUtil.simplePost(
                    fence_token_url,
                    new StringEntity(query_string),
                    JAXRSConfiguration.client,
                    JAXRSConfiguration.objectMapper,
                    headers.toArray(new Header[headers.size()])
            );
        } catch (Exception ex) {
            logger.error("getFENCEAccessToken() failed to call FENCE token service, "+ex.getMessage());
        }
        logger.debug("getFENCEAccessToken() finished: "+resp.asText());
        return resp;
    }

    // Get access_token from FENCE, based on the provided `code`
    public Response getFENCEProfile(String callback_url, Map<String, String> authRequest){
        logger.debug("getFENCEProfile() starting...");
        String fence_code  = authRequest.get("code");

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
	            
	            logger.trace("getFENCEProfile() user profile structure:"+  prettyString);
            }
            logger.debug("getFENCEProfile() .username:" + fence_user_profile.get("username"));
            logger.debug("getFENCEProfile() .user_id:" + fence_user_profile.get("user_id"));
            logger.debug("getFENCEProfile() .email:" + fence_user_profile.get("email"));
        } catch (Exception ex) {
            logger.error("getFENCEProfile() could not retrieve the user profile from the auth provider, because "+ex.getMessage(), ex);
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
            
            //clear some cache entries if we register a new login
            AuthorizationService.clearCache(current_user);
            UserService.clearCache(current_user);

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
            
            // These two special access does not matter. We are not using it.
            if (access_role_name.equals("admin") || access_role_name.equals("parent")) {
            	logger.info("SKIPPING ACCESS ROLE: " + access_role_name);
                continue;
            }
            //topmed ==> access to all studies (not just topmed)
            if (access_role_name.equals("topmed") ) {
            	Map<String, Map> projects = getFENCEMapping();
            	for(Map projectMetadata : projects.values()) {
					String projectId = (String) projectMetadata.get("study_identifier");
					String consentCode = (String) projectMetadata.get("consent_group_code");
					String newRoleName =  "FENCE_"+projectId+"_"+consentCode;
					
					 if (upsertRole(current_user, newRoleName, "FENCE role "+newRoleName)) {
	                    logger.info("getFENCEProfile() Updated TOPMED user role. Now it includes `"+newRoleName+"`");
	                } else {
	                    logger.error("getFENCEProfile() could not add roles to TOPMED user's profile");
	                }
            	}
            	continue;
            }
            
           
            String[] parts = access_role_name.split("\\.");

            String newRoleName;
            if (parts.length > 1) {
               newRoleName = "FENCE_"+parts[0]+"_"+parts[parts.length-1];
            } else {
              newRoleName = "FENCE_"+access_role_name;
            }
            logger.info("getFENCEProfile() New PSAMA role name:"+newRoleName);

                if (upsertRole(current_user, newRoleName, "FENCE role "+newRoleName)) {
                    logger.info("getFENCEProfile() Updated user role. Now it includes `"+newRoleName+"`");
                } else {
                    logger.error("getFENCEProfile() could not add roles to user's profile");
                }

                // TODO: In case we need to do something with this part, we can uncomment it.
                //JsonNode role_object = fence_user_profile.get("project_access").get(newRoleName);
                //It is a an array of strings, like this: ["read-storage","read"]
                //logger.debug("getFENCEProfile() object:"+role_object.toString());
        }

        final String idp = extractIdp(current_user);

        if (current_user.getRoles() != null && (current_user.getRoles().size() > 0 || openAccessIdpValues.contains(idp))) {
	        Role openAccessRole = roleRepo.getUniqueResultByColumn("name", fence_open_access_role_name);
	        if (openAccessRole != null) {
	        	current_user.getRoles().add(openAccessRole);
	        } else {
	        	logger.warn("Unable to find fence OPEN ACCESS role");
	        }
        }
        
        
        try {
            userRepo.changeRole(current_user, current_user.getRoles());
            logger.debug("upsertRole() updated user, who now has "+current_user.getRoles().size()+" roles.");
        } catch (Exception ex) {
            logger.error("upsertRole() Could not add roles to user, because "+ex.getMessage());
        }
        HashMap<String, Object> claims = new HashMap<String,Object>();
        claims.put("name", fence_user_profile.get("name"));
        claims.put("email", current_user.getEmail());
        claims.put("sub", current_user.getSubject());
        HashMap<String, String> responseMap = authUtil.getUserProfileResponse(claims);
        logger.info("LOGIN SUCCESS ___ " + current_user.getEmail() + ":" + current_user.getUuid().toString() + ":" + current_user.getSubject() + " ___ Authorization will expire at  ___ " + responseMap.get("expirationDate") + "___");
        logger.debug("getFENCEProfile() UserProfile response object has been generated");
        logger.debug("getFENCEToken() finished");
        return PICSUREResponse.success(responseMap);
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

        User actual_user = userRepo.findOrCreate(new_user);

        // Clear current set of roles every time we create or retrieve a user
        actual_user.setRoles(new HashSet<>());
        logger.debug("createUserFromFENCEProfile() cleared roles");

        userRepo.persist(actual_user);
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
    private boolean upsertRole(User u,  String roleName, String roleDescription) {
        boolean status = false;
        logger.debug("upsertRole() starting for user subject:"+u.getSubject());

        // Get the User's list of Roles. The first time, this will be an empty Set.
        // This method is called for every Role, and the User's list of Roles will
        // be updated for all subsequent calls.
        try {
            Role r = null;
            // Create the Role in the repository, if it does not exist. Otherwise, add it.
            Role existing_role = roleRepo.getUniqueResultByColumn("name", roleName);
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
                roleRepo.persist(r);
                logger.info("upsertRole() created new role");
            }
            u.getRoles().add(r);
            status = true;
        } catch (Exception ex) {
            logger.error("upsertRole() Could not inser/update role "+roleName+" to repo", ex);
        }


        logger.debug("upsertRole() finished");
        return status;
    }

    private Set<Privilege> addFENCEPrivileges(User u, Role r) {
        String roleName = r.getName();
        logger.info("addFENCEPrivileges() starting, adding privilege(s) to role "+roleName);

        //each project can have up to three privileges: Parent  |  Harmonized  | Topmed
        //harmonized has 2 ARs for parent + harminized and harmonized only
        //Topmed has up to three ARs for topmed / topmed + parent / topmed + harmonized 
        Set<Privilege> privs = r.getPrivileges();
        if (privs == null) { privs = new HashSet<Privilege>();}
        
        //e.g. FENCE_phs0000xx_c2
        String[] parts = roleName.split("_");
        String project_name = parts[1];
        String consent_group = parts[2];
        
        
        // Look up the metadata by consent group.
       Map projectMetadata = getFENCEMappingforProjectAndConsent(project_name, consent_group);
        
        if(projectMetadata == null || projectMetadata.size() == 0) {
        	//no privileges means no access to this project.  just return existing set of privs.
        	logger.warn("No metadata available for project " + project_name + "." + consent_group);
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
            logger.info("addPrivileges() project:"+project_name+" consent_group:"+consent_group+" concept_path:"+concept_path);
            privs.add(upsertClinicalPrivilege(project_name, projectAlias, consent_group, concept_path, false));
            
            //if harmonized study, also create harmonized privileges
            if(Boolean.TRUE.equals(isHarmonized)) {
            	privs.add(upsertClinicalPrivilege(project_name, projectAlias, consent_group, concept_path, true));
            }
        }
        
        //projects without G or P in data_type are skipped
        if(dataType == null || (!dataType.contains("P")  && !dataType.contains("G"))){
        	logger.warn("Missing study type for " + project_name + " " + consent_group);
        }
            
        logger.info("addPrivileges() Finished");
        return privs;
    }

    /**
     * Creates a privilege with a set of access rules that allow queries containing a consent group to pass if the query only contains valid entries that match conceptPath.  If the study is harmonized, 
     * this also creates an access rule to allow access when using the harmonized consent concept path.
     * 
     * Privileges created with this method will deny access if any genomic filters (topmed data) are included.
     * 
     * @param studyIdentifier
     * @param consent_group
     * @param conceptPath
     * @param isHarmonized
     * @return
     */
    private Privilege upsertClinicalPrivilege(String studyIdentifier, String projectAlias, String consent_group, String conceptPath, boolean isHarmonized) {
    	
    	String privilegeName = "PRIV_FENCE_"+studyIdentifier+"_"+consent_group+(isHarmonized?"_HARMONIZED":"");
    	Privilege priv = privilegeRepo.getUniqueResultByColumn("name", privilegeName);
    	if(priv !=  null) {
    		 logger.info("upsertClinicalPrivilege() " + privilegeName + " already exists");
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
            String queryTemplateText = "{\"categoryFilters\": {\""
                    +consent_concept_path
                    +"\":[\""
                    +studyIdentifier+"."+consent_group
                    +"\"]},"
                    +"\"numericFilters\":{},\"requiredFields\":[],"
                    +"\"fields\":[\"" + parentAccessionField + "\"],"
                    +"\"variantInfoFilters\":[{\"categoryVariantInfoFilters\":{},\"numericVariantInfoFilters\":{}}],"
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
            	accessruleRepo.merge(ar);
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
        		ar.getSubAccessRule().add(createPhenotypeSubRule(fence_topmed_consent_group_concept_path, "ALLOW_TOPMED_CONSENT", "$..categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "", true));
            	
        		accessruleRepo.merge(ar);
            }
            accessrules.add(ar);
            
            if(isHarmonized) {
				//add a rule for accessing only harmonized data
				ar = createConsentAccessRule(studyIdentifier, consent_group, "HARMONIZED", fence_harmonized_consent_group_concept_path);
	                
	            //if this is a new rule, we need to populate it
				 if(ar.getGates() == null) {
                	ar.setGates(new HashSet<AccessRule>());
                	ar.getGates().add(upsertConsentGate("HARMONIZED_CONSENT", "$..categoryFilters." + fence_harmonized_consent_group_concept_path + "[*]", true, "harmonized data"));
             	
	            	if(ar.getSubAccessRule() == null) {
                  		ar.setSubAccessRule(new HashSet<AccessRule>());
                  	}
	            	ar.getSubAccessRule().addAll(getAllowedQueryTypeRules());
	            	ar.getSubAccessRule().addAll(getHarmonizedSubRules());
	            	ar.getSubAccessRule().addAll(getPhenotypeSubRules(studyIdentifier, conceptPath, projectAlias));
	            	accessruleRepo.merge(ar);
	            }
	            accessrules.add(ar);
            }
            
            // Add additional access rules;   (these are still created through that SQL script)
            for(String arName: fence_standard_access_rules.split(",")) {
                if (arName.startsWith("AR_")) {
                    logger.info("upsertClinicalPrivilege() Adding AccessRule "+arName+" to privilege "+priv.getName());
                    ar = accessruleRepo.getUniqueResultByColumn("name",arName);
                    if(ar != null) {
                    	accessrules.add(ar);
                    }
                    else {
                    	logger.warn("upsertClinicalPrivilege() unable to find an access rule with name " + arName);
                    }
                }
            }
            priv.setAccessRules(accessrules);
            logger.info("createNewPrivilege() Added "+accessrules.size()+" access_rules to privilege");

            privilegeRepo.persist(priv);
            logger.info("createNewPrivilege() Added new privilege "+priv.getName()+" to DB");
        } catch (Exception ex) {
            ex.printStackTrace();
            logger.error("createNewPrivilege() could not save privilege");
        }
        return priv;
    }
    
    private Set<AccessRule> getAllowedQueryTypeRules() {
    	Set<AccessRule> rules = new HashSet<AccessRule>();
    	String[] allowedTypes = JAXRSConfiguration.fence_allowed_query_types.split(",");
    	for(String queryType : allowedTypes) {
    		
    		String ar_name = "AR_ALLOW_" + queryType ;
    		
    		AccessRule ar = accessruleRepo.getUniqueResultByColumn("name", ar_name);
            if(ar != null) {
            	logger.debug("createTopmedRestrictedSubRule() Found existing rule: " + ar.getName());
            	rules.add(ar);
            	continue;
            }
    		
 	        logger.info("upsertPhenotypeSubRule() Creating new access rule "+ar_name);
 	        ar = new AccessRule();
 	        ar.setName(ar_name);
 	        ar.setDescription("FENCE SUB AR to allow " + queryType + " Queries");
 	        ar.setRule( "$..expectedResultType");
 	        ar.setType(AccessRule.TypeNaming.ALL_EQUALS);
 	        ar.setValue(queryType);
 	        ar.setCheckMapKeyOnly(false);
 	        ar.setCheckMapNode(false);
 	        ar.setEvaluateOnlyByGates(false);
 	        ar.setGateAnyRelation(false); 
 	       
 	        accessruleRepo.persist(ar);
 	       rules.add(ar);
    		
    	}
    	return rules;
	}

	private Collection<? extends AccessRule> getTopmedRestrictedSubRules() {
    	Set<AccessRule> rules = new HashSet<AccessRule>();
    	rules.add(upsertTopmedRestrictedSubRule("CATEGORICAL", "$..variantInfoFilters[*].categoryVariantInfoFilters.*"));
    	rules.add(upsertTopmedRestrictedSubRule("NUMERIC", "$..variantInfoFilters[*].numericVariantInfoFilters.*"));
    	
    	return rules;
	}
    
    //topmed restriction rules don't need much configuration.  Just deny all access.
    private AccessRule upsertTopmedRestrictedSubRule(String type, String rule) {
        String ar_name = "AR_TOPMED_RESTRICTED_" + type;

        AccessRule ar = accessruleRepo.getUniqueResultByColumn("name", ar_name);
        if(ar != null) {
        	logger.debug("createTopmedRestrictedSubRule() Found existing rule: " + ar.getName());
        	return ar;
        }
        
        logger.info("upsertTopmedRestrictedSubRule() Creating new access rule "+ar_name);
        ar = new AccessRule();
        ar.setName(ar_name);
        ar.setDescription("FENCE SUB AR for retricting " + type + " genomic concepts");
        ar.setRule(rule);
        ar.setType(AccessRule.TypeNaming.IS_EMPTY);
        ar.setValue(null);
        ar.setCheckMapKeyOnly(false);
        ar.setCheckMapNode(false);
        ar.setEvaluateOnlyByGates(false);
        ar.setGateAnyRelation(false); 
        
        accessruleRepo.persist(ar);

        return ar;
    }

	private Collection<? extends AccessRule> getPhenotypeSubRules(String studyIdentifier, String conceptPath, String alias) {
    	
    	Set<AccessRule> rules = new HashSet<AccessRule>();
    	//categorical filters will always contain at least one entry (for the consent groups); it will never be empty
    	rules.add(createPhenotypeSubRule(fence_parent_consent_group_concept_path, "ALLOW_PARENT_CONSENT", "$..categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "", true));
    	
    	for(String underscorePath : underscoreFields ) {
    		rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$..fields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "FIELDS", false));
    		rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$..categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "CATEGORICAL", true));
    		rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$..requiredFields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "REQ_FIELDS", false));
    	}
    	
    	rules.add(createPhenotypeSubRule(conceptPath, alias+ "_" + studyIdentifier, "$..categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "CATEGORICAL", true));
    	rules.add(createPhenotypeSubRule(conceptPath, alias+ "_" + studyIdentifier, "$..numericFilters", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "NUMERIC", true));
    	rules.add(createPhenotypeSubRule(conceptPath, alias+ "_" + studyIdentifier, "$..fields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "FIELDS", false));
    	rules.add(createPhenotypeSubRule(conceptPath, alias+ "_" + studyIdentifier, "$..requiredFields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "REQUIRED_FIELDS", false));
    	
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
    	rules.add(createPhenotypeSubRule(fence_parent_consent_group_concept_path, "ALLOW_PARENT_CONSENT", "$..categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "", true));
    	rules.add(createPhenotypeSubRule(fence_harmonized_consent_group_concept_path, "ALLOW_HARMONIZED_CONSENT", "$..categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "", true));
    	rules.add(createPhenotypeSubRule(fence_topmed_consent_group_concept_path, "ALLOW_TOPMED_CONSENT", "$..categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "", true));
    	
    	for(String underscorePath : underscoreFields ) {
    		rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$..fields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "FIELDS", false));
    		rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$..categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "CATEGORICAL", true));
    		rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$..requiredFields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "REQ_FIELDS", false));
    	}
    	
    	rules.add(createPhenotypeSubRule(fence_harmonized_concept_path, "HARMONIZED", "$..categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "CATEGORICAL", true));
    	rules.add(createPhenotypeSubRule(fence_harmonized_concept_path, "HARMONIZED", "$..numericFilters", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "NUMERIC", true));
    	rules.add(createPhenotypeSubRule(fence_harmonized_concept_path, "HARMONIZED", "$..fields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "FIELDS", false));
    	rules.add(createPhenotypeSubRule(fence_harmonized_concept_path, "HARMONIZED", "$..requiredFields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "REQUIRED_FIELDS", false));
    	
    	return rules;
	}
	

	/**
	 * generate and return a set of rules that disallow access to phenotype data (only genomic filters allowed)
	 * @return
	 */
	private Collection<? extends AccessRule> getPhenotypeRestrictedSubRules(String studyIdentifier, String consentCode, String alias) {
    	
    	Set<AccessRule> rules = new HashSet<AccessRule>();
    	//categorical filters will always contain at least one entry (for the consent groups); it will never be empty
    	rules.add(createPhenotypeSubRule(fence_topmed_consent_group_concept_path, "ALLOW_TOPMED_CONSENT", "$..categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "", true));
    	
    	for(String underscorePath : underscoreFields ) {
    		rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$..fields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "FIELDS", false));
    		rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$..categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "CATEGORICAL", true));
    		rules.add(createPhenotypeSubRule(underscorePath, "ALLOW " + underscorePath, "$..requiredFields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "REQ_FIELDS", false));
    	}
    	
    	rules.add(createPhenotypeSubRule(null, alias + "_" + studyIdentifier+ "_" + consentCode, "$..numericFilters.[*]", AccessRule.TypeNaming.IS_EMPTY, "DISALLOW_NUMERIC", false));
//    	rules.add(createPhenotypeSubRule(null, alias + "_" + studyIdentifier+ "_" + consentCode, "$..fields.[*]", AccessRule.TypeNaming.IS_EMPTY, "DISALLOW FIELDS", false, parentRule));
    	rules.add(createPhenotypeSubRule(null, alias + "_" + studyIdentifier+ "_" + consentCode, "$..requiredFields.[*]", AccessRule.TypeNaming.IS_EMPTY, "DISALLOW_REQUIRED_FIELDS", false));
    	
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
    	gates.add(upsertConsentGate("PARENT_CONSENT", "$..categoryFilters." + fence_parent_consent_group_concept_path + "[*]", parent, "parent study data"));
    	gates.add(upsertConsentGate("HARMONIZED_CONSENT", "$..categoryFilters." + fence_harmonized_consent_group_concept_path + "[*]", harmonized, "harmonized data"));
    	gates.add(upsertConsentGate("TOPMED_CONSENT", "$..categoryFilters." + fence_topmed_consent_group_concept_path + "[*]", topmed, "Topmed data"));
   		
		return gates;
	}
	
	 private AccessRule createPhenotypeSubRule(String conceptPath, String alias, String rule, int ruleType, String label, boolean useMapKey) {
	        
		 	//remove double escape sequence from path evaluation expression
		 	if(conceptPath != null && conceptPath.contains("\\\\")) {
		 		//replaceall regex needs to be double escaped (again)
		 		conceptPath = conceptPath.replaceAll("\\\\\\\\", "\\\\");
		 	}
		 
		 	String ar_name = "AR_PHENO_"+alias + "_" + label;
		 	
		 	AccessRule ar = accessruleRepo.getUniqueResultByColumn("name", ar_name);
	        if(ar != null) {
	        	logger.debug("createPhenotypeSubRule() Found existing rule: " + ar.getName());
	        	return ar;
	        }
		 	
	        logger.info("createPhenotypeSubRule() Creating new access rule "+ar_name);
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
	        
	        accessruleRepo.persist(ar);

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
    	Privilege priv = privilegeRepo.getUniqueResultByColumn("name", privilegeName);
    	if(priv !=  null) {
    		 logger.info("upsertTopmedPrivilege() " + privilegeName + " already exists");
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
           	logger.debug("upsertTopmedPrivilege(): escaped parent consent path" + consent_concept_path);
           }
            
            if(fence_harmonized_concept_path != null && !fence_harmonized_concept_path.contains("\\\\")){
	          	 //these have to be escaped again so that jaxson can convert it correctly
	        	fence_harmonized_concept_path = fence_harmonized_concept_path.replaceAll("\\\\", "\\\\\\\\");
	           	logger.debug("upsertTopmedPrivilege(): escaped harmonized consent path" + fence_harmonized_concept_path);
            }
            
            // TODO: Change this to a mustache template
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
            
            

    		String variantColumns = JAXRSConfiguration.variantAnnotationColumns;
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
        		accessruleRepo.merge(ar);
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
            		ar.getSubAccessRule().add(createPhenotypeSubRule(fence_topmed_consent_group_concept_path, "ALLOW_TOPMED_CONSENT", "$..categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "", true));
                	
            		accessruleRepo.merge(ar);
                }
                accessrules.add(ar);
                
                
                if(isHarmonized) {
                	ar = upsertHarmonizedAccessRule(studyIdentifier, consent_group, "HARMONIZED");
                    
                    //if this is a new rule, we need to populate it
                	 if(ar.getGates() == null) {
                      	ar.setGates(new HashSet<AccessRule>());
//                      	ar.getGates().addAll(getGates(true, true, false));
                      	ar.getGates().add(upsertConsentGate("HARMONIZED_CONSENT", "$..categoryFilters." + fence_harmonized_consent_group_concept_path + "[*]", true, "harmonized data"));
                     	
                     	if(ar.getSubAccessRule() == null) {
                     		ar.setSubAccessRule(new HashSet<AccessRule>());
                     	}
                     	ar.getSubAccessRule().addAll(getAllowedQueryTypeRules());
                		ar.getSubAccessRule().addAll(getHarmonizedSubRules());
                		ar.getSubAccessRule().addAll(getPhenotypeSubRules(studyIdentifier, parentConceptPath, projectAlias));
                		accessruleRepo.merge(ar);
                    }
                    accessrules.add(ar);
                    
                    
//                	ar = upsertHarmonizedAccessRule(studyIdentifier, consent_group, "TOPMED+HARMONIZED+PARENT");
//                    
//                    //if this is a new rule, we need to populate it
//                	 if(ar.getGates() == null) {
//                       	ar.setGates(new HashSet<AccessRule>());
//                       	ar.getGates().addAll(getGates(true, true, true));
//                      	
//                      	if(ar.getSubAccessRule() == null) {
//                      		ar.setSubAccessRule(new HashSet<AccessRule>());
//                      	}
//                      	ar.getSubAccessRule().addAll(getAllowedQueryTypeRules());
//                    	ar.getSubAccessRule().addAll(getPhenotypeSubRules(studyIdentifier, parentConceptPath,  projectAlias));
//                		ar.getSubAccessRule().addAll(getHarmonizedSubRules());
//                		ar.getSubAccessRule().add(createPhenotypeSubRule(fence_topmed_consent_group_concept_path, "ALLOW_TOPMED_CONSENT", "$..categoryFilters", AccessRule.TypeNaming.ALL_CONTAINS, "", true));
//                    	
//                		accessruleRepo.merge(ar);
//                    }
//                    accessrules.add(ar);
                }
            	
            }
            
            // Add additional access rules;  
            for(String arName: fence_standard_access_rules.split(",")) {
                if (arName.startsWith("AR_")) {
                    logger.info("upsertTopmedPrivilege() Adding AccessRule "+arName+" to privilege "+priv.getName());
                    ar = accessruleRepo.getUniqueResultByColumn("name",arName);
                    if(ar != null) {
                    	accessrules.add(ar);
                    }
                    else {
                    	logger.warn("uupsertTopmedPrivilege() nable to find an access rule with name " + arName);
                    }
                }
            }
            priv.setAccessRules(accessrules);
            logger.info("upsertTopmedPrivilege() Added "+accessrules.size()+" access_rules to privilege");

            privilegeRepo.persist(priv);
            logger.info("upsertTopmedPrivilege() Added new privilege "+priv.getName()+" to DB");
        } catch (Exception ex) {
            ex.printStackTrace();
            logger.error("upsertTopmedPrivilege() could not save privilege");
        }
        return priv;
    }

    //Generates Main rule only; gates & sub rules attached after calling this
	// prentRule should be null if this is the main rule, or the appropriate value if this is a sub rule
    private AccessRule createConsentAccessRule(String studyIdentifier, String consent_group, String label, String consent_path) {
        logger.debug("upsertConsentAccessRule() starting");
        String ar_name = "AR_CONSENT_" + studyIdentifier+"_"+consent_group+ "_" +label;

        AccessRule ar = accessruleRepo.getUniqueResultByColumn("name", ar_name);
        if(ar != null) {
        	logger.debug("upsertConsentAccessRule() Found existing rule: " + ar.getName());
        	return ar;
        }
        
        
        
        logger.info("upsertConsentAccessRule() Creating new access rule "+ar_name);
        ar = new AccessRule();
        ar.setName(ar_name);
        ar.setDescription("FENCE AR for "+studyIdentifier+"."+consent_group + " clinical concepts");
        StringBuilder ruleText = new StringBuilder();
        ruleText.append("$..categoryFilters.");
        ruleText.append(consent_path);
        ruleText.append("[*]");
        ar.setRule(ruleText.toString());
        ar.setType(AccessRule.TypeNaming.ALL_CONTAINS);
        ar.setValue(studyIdentifier+"."+consent_group);
        ar.setCheckMapKeyOnly(false);
        ar.setCheckMapNode(false);
        ar.setEvaluateOnlyByGates(false);
        ar.setGateAnyRelation(false); 

        accessruleRepo.persist(ar);

        logger.debug("upsertConsentAccessRule() finished");
        return ar;
    }
    
    // Generates Main Rule only; gates & sub rules attached by calling method
    private AccessRule upsertTopmedAccessRule(String project_name, String consent_group, String label ) {
        logger.debug("upsertTopmedAccessRule() starting");
        String ar_name = "AR_TOPMED_"+project_name+"_"+consent_group + "_" + label;
        AccessRule ar = accessruleRepo.getUniqueResultByColumn("name", ar_name);
        if (ar != null) {
            logger.info("upsertTopmedAccessRule() AccessRule "+ar_name+" already exists.");
            return ar;
        }

        logger.info("upsertTopmedAccessRule() Creating new access rule "+ar_name);
        ar = new AccessRule();
        ar.setName(ar_name);
        ar.setDescription("FENCE AR for "+project_name+"."+consent_group + " Topmed data");
        StringBuilder ruleText = new StringBuilder();
        ruleText.append("$..categoryFilters.");
        ruleText.append(fence_topmed_consent_group_concept_path);
        ruleText.append("[*]");
        ar.setRule(ruleText.toString());
        ar.setType(AccessRule.TypeNaming.ALL_CONTAINS);
        ar.setValue(project_name+"."+consent_group);
        ar.setCheckMapKeyOnly(false);
        ar.setCheckMapNode(false);
        ar.setEvaluateOnlyByGates(false);
        ar.setGateAnyRelation(false);  
        
        accessruleRepo.persist(ar);

        logger.debug("upsertTopmedAccessRule() finished");
        return ar;
    }
    
    
    // Generates Main Rule only; gates & sub rules attached by calling method
    private AccessRule upsertHarmonizedAccessRule(String project_name, String consent_group, String label ) {
        logger.debug("upsertTopmedAccessRule() starting");
        String ar_name = "AR_TOPMED_"+project_name+"_"+consent_group + "_" + label;
        AccessRule ar = accessruleRepo.getUniqueResultByColumn("name", ar_name);
        if (ar != null) {
            logger.info("upsertTopmedAccessRule() AccessRule "+ar_name+" already exists.");
            return ar;
        }

        logger.info("upsertTopmedAccessRule() Creating new access rule "+ar_name);
        ar = new AccessRule();
        ar.setName(ar_name);
        ar.setDescription("FENCE AR for "+project_name+"."+consent_group + " Topmed data");
        StringBuilder ruleText = new StringBuilder();
        ruleText.append("$..categoryFilters.");
        ruleText.append(fence_harmonized_consent_group_concept_path);
        ruleText.append("[*]");
        ar.setRule(ruleText.toString());
        ar.setType(AccessRule.TypeNaming.ALL_CONTAINS);
        ar.setValue(project_name+"."+consent_group);
        ar.setCheckMapKeyOnly(false);
        ar.setCheckMapNode(false);
        ar.setEvaluateOnlyByGates(false);
        ar.setGateAnyRelation(false);  
        
        accessruleRepo.persist(ar);

        logger.debug("upsertTopmedAccessRule() finished");
        return ar;
    }

    /**
     * Insert a new gate (if it doesn't exist yet) to identify if consent values are present in the query.   
     * return an existing gate named GATE_{gateName}_(PRESENT|MISSING) if it exists.
     */
	private AccessRule upsertConsentGate(String gateName, String rule, boolean is_present, String description) {
		
		gateName = "GATE_" + gateName + "_" + (is_present ? "PRESENT": "MISSING");
		
	    AccessRule gate = accessruleRepo.getUniqueResultByColumn("name", gateName);
        if (gate != null) {
            logger.info("upsertConsentGate() AccessRule "+gateName+" already exists.");
            return gate;
        }

        logger.info("upsertClinicalGate() Creating new access rule "+gateName);
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
        
        accessruleRepo.persist(gate);
		return gate;
	}
	
	private Map getFENCEMappingforProjectAndConsent(String projectId, String consent_group) {
	
		String consentVal = projectId + "." + consent_group;
		logger.info("getFENCEMappingforProjectAndConsent() looking up "+consentVal);
			 
		Object projectMetadata = getFENCEMapping().get(consentVal);
		if( projectMetadata instanceof Map) {
			return (Map)projectMetadata;
		} else if (projectMetadata != null) {
			logger.info("getFENCEMappingforProjectAndConsent() Obj instance of " + projectMetadata.getClass().getCanonicalName());	
		}
		return null;
	}
	
	private Map<String, Map> getFENCEMapping(){
		if(_projectMap == null || _projectMap.isEmpty()) {
			try {
				Map fenceMapping = JAXRSConfiguration.objectMapper.readValue(
						new File(String.join(File.separator,
								new String[] {JAXRSConfiguration.templatePath ,"fence_mapping.json"}))
						, Map.class);
				List<Map> projects = (List<Map>) fenceMapping.get("bio_data_catalyst");
				logger.debug("getFENCEMapping: found FENCE mapping with " + projects.size() + " entries");
				_projectMap = new HashMap<String, Map>(projects.size());
				for(Map project : projects) {
					String consentVal = "" + project.get("study_identifier") + "." + project.get("consent_group_code");
					logger.debug("adding study " + consentVal);
					_projectMap.put(consentVal, project);
				}
				
			} catch (Exception e) {
				logger.error("getFENCEMapping: Non-fatal error parsing fence_mapping.json: "+JAXRSConfiguration.templatePath, e);
				return new HashMap<String,Map>();
			}
		}
		
		return _projectMap;
	}
}
