package edu.harvard.hms.dbmi.avillach.auth.service.auth;

import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_parent_consent_group_concept_path;
import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_harmonized_concept_path;
import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_harmonized_consent_group_concept_path;
import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_standard_access_rules;
import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_topmed_consent_group_concept_path;

import java.io.File;
import java.io.IOException;
import java.util.*;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.Response;

import org.apache.http.Header;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;

import edu.harvard.dbmi.avillach.util.HttpClientUtil;
import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.*;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.*;
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
        logger.debug("getFENCEAccessToken() finished. "+resp.asText());
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
            logger.error("getFENCEToken() could not retrieve the user profile from the auth provider, because "+ex.getMessage(), ex);
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
            	Collection<Map> projects = getFENCEMappingForAllProjects();
            	for(Map projectMetadata : projects) {
					String projectId = (String) projectMetadata.get("study_identifer");
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
        logger.debug("getFENCEProfile() UserProfile response object has been generated");

        logger.debug("getFENCEToken() finished");
        return PICSUREResponse.success(responseMap);
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
        logger.info("addPrivileges() starting, adding privilege(s) to role "+roleName);

        //each project can have up to three privileges: Parent  |  Harmonized  | Topmed
        //harmonized has 2 ARs for parent + harminized and harmonized only
        //Topmed has up to four ARs for topmed / topmed + parent / topmed + harmonized / topmed + parent + harmonized
        Set<Privilege> privs = r.getPrivileges();
        if (privs == null) { privs = new HashSet<Privilege>();}
        
        //e.g. FENCE_phs0000xx_c2
        String[] parts = roleName.split("_");
        String project_name = parts[1];
        String consent_group = parts[2];
        
        
        // 
       Map projectMetadata = getFENCEMappingforProjectAndConsent(project_name, consent_group);
        
        if(projectMetadata == null || projectMetadata.size() == 0) {
        	// TODO: Assign NO ACCESS privilege here
        	//... but then how do we clear that out if there's new metadata to fix it? (whole DB gets cleared! -nc)
        	logger.debug("NO metadata available for project " + project_name + " : " + consent_group);
        	return privs;
        }
        
        logger.info("addPrivileges() This is a new privilege");
        
        
        
        String dataType = (String) projectMetadata.get("data_type");
        Boolean isHarmonized = "Y".equals(projectMetadata.get("isHarmonized"));
        String concept_path = (String) projectMetadata.get("top_level_path");
        
        //we need to add escape sequence back in to the path for parsing later (also need to double escape the regex)
        if(concept_path != null) {
        	concept_path = concept_path.replaceAll("\\\\", "\\\\\\\\");
        }
        
        if(dataType != null && dataType.contains("G")) {
        	//insert genomic/topmed privs - this will also add rules for including harmonized & parent data if applicable
        	privs.add(upsertTopmedPrivilege(project_name, consent_group, concept_path, isHarmonized));
        }
        
        if(dataType != null && dataType.contains("P")) {
        	//insert clinical privs
            logger.info("addPrivileges() project:"+project_name+" consent_group:"+consent_group+" concept_path:"+concept_path);

            // Add new privilege PRIV_FENCE_phs######_c# and PRIV_FENCE_phs######_c#_HARMONIZED
            privs.add(upsertClinicalPrivilege(project_name, consent_group, concept_path, false));
            
            //if harmonized study, also create harmonized privileges
            if(Boolean.TRUE.equals(isHarmonized)) {
            	privs.add(upsertClinicalPrivilege(project_name, consent_group, concept_path, true));
            }
        	
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
     * @param project_name
     * @param consent_group
     * @param conceptPath
     * @param isHarmonized
     * @return
     */
    private Privilege upsertClinicalPrivilege(String project_name, String consent_group, String conceptPath, boolean isHarmonized) {
    	
    	
    	String privilegeName = "PRIV_FENCE_"+project_name+"_"+consent_group+(isHarmonized?"_HARMONIZED":"");
    	Privilege priv = privilegeRepo.getUniqueResultByColumn("name", privilegeName);
    	if(priv !=  null) {
    		 logger.info("upsertClinicalPrivilege() " + privilegeName + " already exists");
    		return priv;
    	}
    	
        priv = new Privilege();

        try {
        	
        	
        	
            priv.setApplication(picSureApp);
            priv.setName(privilegeName);
            priv.setDescription("FENCE privilege for "+project_name+"/"+consent_group+(isHarmonized?" harmonized data":""));

            String consent_concept_path = isHarmonized ? fence_harmonized_consent_group_concept_path : fence_parent_consent_group_concept_path;
            // TOOD: Change this to a mustache template
            String queryTemplateText = "{\"categoryFilters\": {\""
                    +consent_concept_path
                    +"\":\""
                    +project_name+"."+consent_group
                    +"\"},"
                    +"\"numericFilters\":{},\"requiredFields\":[],"
                    +"\"variantInfoFilters\":[{\"categoryVariantInfoFilters\":{},\"numericVariantInfoFilters\":{}}],"
                    +"\"expectedResultType\": \"COUNT\""
                    +"}";
            priv.setQueryTemplate(queryTemplateText);
            priv.setQueryScope("[\"" + conceptPath + "\"]");

            Set<AccessRule> accessrules = new HashSet<AccessRule>();
            
            //parent

            if(isHarmonized) {
            	//harmonized data has two ARs; one for _only_ harmonized, and one for a mix of harmonized and parent concepts
            	AccessRule ar = upsertConsentAccessRule(project_name, consent_group, "PARENT_HARMONIZED", fence_harmonized_consent_group_concept_path);
                
                //if this is a new rule, we need to populate it
                if(ar.getGates().size() == 0) {
                	ar.getGates().addAll(getGates(true, true, false));
                	ar.getSubAccessRule().addAll(getPhenotypeSubRules(conceptPath));
            		ar.getSubAccessRule().addAll(getPhenotypeSubRules(fence_harmonized_concept_path));
            		ar.getSubAccessRule().addAll(getTopmedRestrictedSubRules());
            		ar.getSubAccessRule().add(upsertConsentAccessRule(project_name, consent_group, "HARMONIZED_SUB_RULE", fence_harmonized_consent_group_concept_path));
            		accessruleRepo.merge(ar);
                }
                accessrules.add(ar);
                
				//also add another rule for accessing only harmonized data
				ar = upsertConsentAccessRule(project_name, consent_group, "HARMONIZED_ONLY", fence_harmonized_consent_group_concept_path);
	                
	            //if this is a new rule, we need to populate it
	            if(ar.getGates().size() == 0) {
	            	ar.getGates().addAll(getGates(false, true, false));
	            	ar.getSubAccessRule().addAll(getPhenotypeSubRules(fence_harmonized_concept_path));
	            	ar.getSubAccessRule().addAll(getTopmedRestrictedSubRules());
	            	accessruleRepo.merge(ar);
	            }
	            accessrules.add(ar);
            } else {
            	// NO HARMONIZED DATA
            	//just need one AR for parent study
	            AccessRule ar = upsertConsentAccessRule(project_name, consent_group, "PARENT_HARMONIZED", fence_parent_consent_group_concept_path);
	            
	            logger.debug("AR" + ar);
	            logger.debug("gates" + ar.getGates());
	            logger.debug("sub rules " + ar.getSubAccessRule());
	            //if this is a new rule, we need to populate it
	            if(ar.getGates() == null) {
	            	ar.setGates(new HashSet<AccessRule>());
	            	ar.getGates().addAll(getGates(true, false, false));
	            	
	            	if(ar.getSubAccessRule() == null) {
	            		ar.setSubAccessRule(new HashSet<AccessRule>());
	            	}
	            	ar.getSubAccessRule().addAll(getPhenotypeSubRules(conceptPath));
	            	ar.getSubAccessRule().addAll(getTopmedRestrictedSubRules());
	            	accessruleRepo.merge(ar);
	            }
	            
	            accessrules.add(ar);
            }
            
            
            // Add additional access rules;   (these are still created through that SQL script I guess)
            for(String arName: fence_standard_access_rules.split(",")) {
                if (arName.startsWith("AR_")) {
                    logger.info("Adding AccessRule "+arName+" to privilege "+priv.getName());
                    accessrules.add(accessruleRepo.getUniqueResultByColumn("name",arName));
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
    
    private Collection<? extends AccessRule> getTopmedRestrictedSubRules() {
    	Set<AccessRule> rules = new HashSet<AccessRule>();
    	//categorical filters will always contain at least one entry (for the consent groups); it will never be empty
    	rules.add(upsertTopmedRestrictedSubRule("CATEGORICAL", "$.query.variantInfoFilters[*].categoryVariantInfoFilters.*"));
    	rules.add(upsertTopmedRestrictedSubRule("NUMERIC", "$.query.variantInfoFilters[*].numericVariantInfoFilters.*"));
    	
    	return rules;
	}
    
    //topmed restriction rules don't need much configuration.  Just deny all access.
    private AccessRule upsertTopmedRestrictedSubRule(String name, String rule) {
        String ar_name = "AR_TOPMED_RESTRICTED_"+name;
        AccessRule ar = accessruleRepo.getUniqueResultByColumn("name", ar_name);
        if (ar != null) {
            logger.info("upsertTopmedRestrictedSubRule() AccessRule "+ar_name+" already exists.");
            return ar;
        }

        logger.info("upsertTopmedRestrictedSubRule() Creating new access rule "+ar_name);
        ar = new AccessRule();
        ar.setName(ar_name);
        ar.setDescription("FENCE SUB AR for retricting " + name + " genomic concepts");
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

	private Collection<? extends AccessRule> getPhenotypeSubRules(String conceptPath) {
    	
    	Set<AccessRule> rules = new HashSet<AccessRule>();
    	//categorical filters will always contain at least one entry (for the consent groups); it will never be empty
    	rules.add(upsertPhenotypeSubRule(conceptPath, "$..categoryFilters.[*]", AccessRule.TypeNaming.ALL_CONTAINS, "CATEGORICAL", true));
    	rules.add(upsertPhenotypeSubRule(conceptPath, "$..numericFilters.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "NUMERIC", true));
    	rules.add(upsertPhenotypeSubRule(conceptPath, "$..fields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "FIELDS", false));
    	rules.add(upsertPhenotypeSubRule(conceptPath, "$..requiredFields.[*]", AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY, "REQUIRED_FIELDS", false));
    	
    	return rules;
	}
	

	//generate and return a set of rules that disallow access to phenotype data
	private Collection<? extends AccessRule> getPhenotypeRestrictedSubRules() {
    	
    	Set<AccessRule> rules = new HashSet<AccessRule>();
    	//Categorical filters not included, because they will always have the consent values (and possibly variant annotations)
    	rules.add(upsertPhenotypeSubRule("DISALLOW_NUMERIC", "$..numericFilters.[*]", AccessRule.TypeNaming.IS_EMPTY, "NUMERIC", false));
    	rules.add(upsertPhenotypeSubRule("DISALLOW_FIELDS", "$..fields.[*]", AccessRule.TypeNaming.IS_EMPTY, "FIELDS", false));
    	rules.add(upsertPhenotypeSubRule("DISALLOW_REQUIRED_FIELDS", "$..requiredFields.[*]", AccessRule.TypeNaming.IS_EMPTY, "REQUIRED_FIELDS", false));
    	
    	return rules;
	}
	
	private Collection<? extends AccessRule> getAllowVariantAnnotationsSubRules() {
		Set<AccessRule> rules = new HashSet<AccessRule>();
		
		String variantColumns = JAXRSConfiguration.variantAnnotationColumns;
		if(variantColumns == null || variantColumns.isEmpty()) {
			logger.debug("getAllowVariantAnnotationsSubRules(): No variant annotations: " + variantColumns);
			return rules;
		}
		
		for(String annotationPath : variantColumns.split(",")) {
			rules.add(upsertPhenotypeSubRule(annotationPath, "$..categoryFilters.[*]", AccessRule.TypeNaming.ALL_CONTAINS, "CATEGORICAL", true));
		}
    	return rules;
	}


	private Collection<? extends AccessRule> getGates(boolean parent, boolean harmonized, boolean topmed) {
    	
    	Set<AccessRule> gates = new HashSet<AccessRule>();
    	gates.add(upsertConsentGate("PARENT_CONSENT", "$..categoryFilters.['" + fence_parent_consent_group_concept_path + "']", parent, "parent study data"));
    	gates.add(upsertConsentGate("HARMONIZED_CONSENT", "$..categoryFilters.['" + fence_harmonized_consent_group_concept_path + "']", harmonized, "harmonized data"));
    	gates.add(upsertConsentGate("TOPMED_CONSENT", "$..categoryFilters.['" + fence_topmed_consent_group_concept_path + "']", topmed, "Topmed data"));
   		
		return gates;
	}
	
	 private AccessRule upsertPhenotypeSubRule(String conceptPath, String rule, int ruleType, String label, boolean useMapKey) {
	        String ar_name = "AR_PHENO_"+conceptPath + "_" + label;
	        AccessRule ar = accessruleRepo.getUniqueResultByColumn("name", ar_name);
	        if (ar != null) {
	            logger.info("upsertPhenotypeSubRule() AccessRule "+ar_name+" already exists.");
	            return ar;
	        }

	        logger.info("upsertPhenotypeSubRule() Creating new access rule "+ar_name);
	        ar = new AccessRule();
	        ar.setName(ar_name);
	        ar.setDescription("FENCE SUB AR for " + conceptPath + " " + label + " clinical concepts");
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
	 * @param project_name
	 * @param consent_group
	 * @return
	 */
	private Privilege upsertTopmedPrivilege(String project_name, String consent_group, String parentConceptPath, boolean isHarmonized) {
		
    	String privilegeName = "PRIV_FENCE_"+project_name+"_"+consent_group + "_TOPMED";
    	Privilege priv = privilegeRepo.getUniqueResultByColumn("name", privilegeName);
    	if(priv !=  null) {
    		 logger.info("upsertClinicalPrivilege() " + privilegeName + " already exists");
    		return priv;
    	}
    	
        priv = new Privilege();


        // Build Privilege Object
        try {
            priv.setApplication(picSureApp);
            priv.setName(privilegeName);
            priv.setDescription("FENCE privilege for Topmed "+project_name+"/"+consent_group);

            // TOOD: Change this to a mustache template
            String queryTemplateText = "{\"categoryFilters\": {\""
                    +fence_topmed_consent_group_concept_path
                    +"\":\""
                    +project_name+"."+consent_group
                    +"\"},"
                    +"\"numericFilters\":{},\"requiredFields\":[],"
                    +"\"variantInfoFilters\":[{\"categoryVariantInfoFilters\":{},\"numericVariantInfoFilters\":{}}],"
                    +"\"expectedResultType\": \"COUNT\""
                    +"}";
            priv.setQueryTemplate(queryTemplateText);
            //need a non-null scope that is a list of strings
            priv.setQueryScope("[]");
            
            Set<AccessRule> accessrules = new HashSet<AccessRule>();
            
            AccessRule ar = upsertTopmedAccessRule(project_name, consent_group, "TOPMED");
            
            //if this is a new rule, we need to populate it
            if(ar.getGates() == null) {
            	ar.setGates(new HashSet<AccessRule>());
            	ar.getGates().addAll(getGates(false, false, true));
            	
            	if(ar.getSubAccessRule() == null) {
            		ar.setSubAccessRule(new HashSet<AccessRule>());
            	}
        		ar.getSubAccessRule().addAll(getPhenotypeRestrictedSubRules());
        		ar.getSubAccessRule().addAll(getAllowVariantAnnotationsSubRules());
        		accessruleRepo.merge(ar);
            }
            accessrules.add(ar);
            
            if(parentConceptPath != null) {
            	
            	ar = upsertTopmedAccessRule(project_name, consent_group, "TOPMED+PARENT");
                
                //if this is a new rule, we need to populate it
            	 if(ar.getGates() == null) {
                 	ar.setGates(new HashSet<AccessRule>());
                	ar.getGates().addAll(getGates(true, false, true));
                	
                	if(ar.getSubAccessRule() == null) {
                		ar.setSubAccessRule(new HashSet<AccessRule>());
                	}
            		ar.getSubAccessRule().addAll(getPhenotypeSubRules(parentConceptPath));
            		ar.getSubAccessRule().add(upsertConsentAccessRule(project_name, consent_group, "PARENT_SUB_RULE", fence_parent_consent_group_concept_path));
            		ar.getSubAccessRule().addAll(getAllowVariantAnnotationsSubRules());
            		accessruleRepo.merge(ar);
                }
                accessrules.add(ar);
                
                
                if(isHarmonized) {
                	//harmonized data has two ARs; one for adding _only_ harmonized, and one for a mix of harmonized and parent concepts
                	ar = upsertTopmedAccessRule(project_name, consent_group, "TOPMED+HARMONIZED");
                    
                    //if this is a new rule, we need to populate it
                	 if(ar.getGates() == null) {
                      	ar.setGates(new HashSet<AccessRule>());
                      	ar.getGates().addAll(getGates(true, true, false));
                     	
                     	if(ar.getSubAccessRule() == null) {
                     		ar.setSubAccessRule(new HashSet<AccessRule>());
                     	}
                		ar.getSubAccessRule().addAll(getPhenotypeSubRules(fence_harmonized_concept_path));
                		ar.getSubAccessRule().add(upsertConsentAccessRule(project_name, consent_group, "HARMONIZED_SUB_RULE", fence_harmonized_consent_group_concept_path));
                		ar.getSubAccessRule().addAll(getAllowVariantAnnotationsSubRules());
                		accessruleRepo.merge(ar);
                    }
                    
                    accessrules.add(ar);
                    
                    
                	ar = upsertTopmedAccessRule(project_name, consent_group, "TOPMED+HARMONIZED+PARENT");
                    
                    //if this is a new rule, we need to populate it
                	 if(ar.getGates() == null) {
                       	ar.setGates(new HashSet<AccessRule>());
                       	ar.getGates().addAll(getGates(true, true, true));
                      	
                      	if(ar.getSubAccessRule() == null) {
                      		ar.setSubAccessRule(new HashSet<AccessRule>());
                      	}
                    	ar.getSubAccessRule().addAll(getPhenotypeSubRules(parentConceptPath));
                		ar.getSubAccessRule().addAll(getPhenotypeSubRules(fence_harmonized_concept_path));
                		ar.getSubAccessRule().add(upsertConsentAccessRule(project_name, consent_group, "PARENT_SUB_RULE", fence_parent_consent_group_concept_path));
                		ar.getSubAccessRule().add(upsertConsentAccessRule(project_name, consent_group, "HARMONIZED_SUB_RULE", fence_harmonized_consent_group_concept_path));
                		accessruleRepo.merge(ar);
                    }
                    
                    accessrules.add(ar);
                }
            	
            }
            
            // Add additional access rules;  
            for(String arName: fence_standard_access_rules.split(",")) {
                if (arName.startsWith("AR_")) {
                    logger.info("Adding AccessRule "+arName+" to privilege "+priv.getName());
                    accessrules.add(accessruleRepo.getUniqueResultByColumn("name",arName));
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

    //Generates Main rule only; gates & sub rules attached after calling this
    private AccessRule upsertConsentAccessRule(String project_name, String consent_group, String label, String consent_path) {
        logger.debug("upsertConsentAccessRule() starting");
        String ar_name = "AR_CLINICAL_" + project_name+"_"+consent_group+ "_" +label;
        AccessRule ar = accessruleRepo.getUniqueResultByColumn("name", ar_name);
        if (ar != null) {
            logger.info("upsertConsentAccessRule() AccessRule "+ar_name+" already exists.");
            return ar;
        }

        logger.info("upsertConsentAccessRule() Creating new access rule "+ar_name);
        ar = new AccessRule();
        ar.setName(ar_name);
        ar.setDescription("FENCE AR for "+project_name+"/"+consent_group + " clinical concepts");
        StringBuilder ruleText = new StringBuilder();
        ruleText.append("$..categoryFilters.['");
        ruleText.append(consent_path);
        ruleText.append("']");
        ar.setRule(ruleText.toString());
        ar.setType(AccessRule.TypeNaming.ALL_EQUALS);
        ar.setValue(project_name+"."+consent_group);
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
        ar.setDescription("FENCE AR for "+project_name+"/"+consent_group + " Topmed data");
        StringBuilder ruleText = new StringBuilder();
        ruleText.append("$..categoryFilters.['");
        ruleText.append(fence_topmed_consent_group_concept_path);
        ruleText.append("']");
        ar.setRule(ruleText.toString());
        ar.setType(AccessRule.TypeNaming.ALL_EQUALS);
        ar.setValue(project_name+"."+consent_group);
        ar.setCheckMapKeyOnly(false);
        ar.setCheckMapNode(false);
        ar.setEvaluateOnlyByGates(false);
        ar.setGateAnyRelation(true);  //one gate per 'categoryFilter/NumericFilter etc.'. one non-null value triggers.

        accessruleRepo.persist(ar);

        logger.debug("upsertTopmedAccessRule() finished");
        return ar;
    }

    /**
     * Insert a new gate if it doesn't exist yet.  
     * return an existing gate named GATE_{gateName} if it exists.
     */
	private AccessRule upsertConsentGate(String gateName, String rule, boolean is_empty, String description) {
		
		gateName = "GATE_" + gateName + "_" + (is_empty ? "MISSING" : "PRESENT");
		
	    AccessRule gate = accessruleRepo.getUniqueResultByColumn("name", gateName);
        if (gate != null) {
            logger.info("upsertConsentGate() AccessRule "+gateName+" already exists.");
            return gate;
        }

        logger.info("upsertClinicalGate() Creating new access rule "+gateName);
        gate = new AccessRule();
        gate.setName(gateName);
        gate.setDescription("FENCE GATE for " + description + " consent present");
        gate.setRule(rule);
        gate.setType(is_empty ? AccessRule.TypeNaming.IS_EMPTY : AccessRule.TypeNaming.IS_NOT_EMPTY);
        gate.setValue(null);  
        gate.setCheckMapKeyOnly(false); 
        gate.setCheckMapNode(false);
        gate.setEvaluateOnlyByGates(false);
        gate.setGateAnyRelation(false); 
        
        accessruleRepo.persist(gate);
		return gate;
	}
	
	private static DocumentContext _parsed_fence_mapping;

	
	private Map getFENCEMappingforProjectAndConsent(String projectId, String consent_group) {
	
		 logger.info("getFENCEMappingforProjectAndConsent() looking up "+projectId + " " + consent_group);
		for(Object projectMetadata : getFENCEMappingforProject(projectId)) {
			 
			if(projectMetadata instanceof Map) {
				
				logger.debug("getFENCEMappingforProjectAndConsent() found obj " + Arrays.deepToString(((Map)projectMetadata).keySet().toArray()));
				String proj_consent_code = (String) ((Map)projectMetadata).get("consent_group_code");
				logger.info("getFENCEMappingforProjectAndConsent() found consent code : " + proj_consent_code);
				if(proj_consent_code != null && proj_consent_code.equals(consent_group)) {
					return (Map)projectMetadata;
				}
			} else {
				logger.info("getFENCEMappingforProjectAndConsent() Obj instance of " + projectMetadata.getClass().getCanonicalName());	
			}
		}
		return null;
	}
	
	/**
	 * Get the mappings of fence privileges
	 * 
	 * 
	 * 
	 */
	private Collection<Map> getFENCEMappingforProject(String projectId) {
		
		if(_parsed_fence_mapping == null) {
			try {
				
				_parsed_fence_mapping = JsonPath.parse(new File(String.join(File.separator,
						new String[] {JAXRSConfiguration.templatePath ,"fence_mapping.json"})));
				
			} catch (IOException e) {
				logger.error("fence_mapping.json not found at "+JAXRSConfiguration.templatePath);
				return new ArrayList<Map>();
			}
		}
		
		//find all objects that have the right project ID.  There could be several, one for each consent group
		// key is "study_identifier"
		String matchProjectJsonPath = "$..[?(@.study_identifer=='"+ projectId+"')]";
		
		Object projects = _parsed_fence_mapping.read(matchProjectJsonPath);
		
		if( ! (projects instanceof Collection) ) {
			//this should not happen
			logger.error("parsed json data does not contain study "+projectId);
			return new ArrayList<Map>();
		}
		
		return (Collection)projects;
	}
	
	private Collection<Map> getFENCEMappingForAllProjects(){
		if(_parsed_fence_mapping == null) {
			try {
				
				_parsed_fence_mapping = JsonPath.parse(new File(String.join(File.separator,
						new String[] {JAXRSConfiguration.templatePath ,"fence_mapping.json"})));
				
			} catch (IOException e) {
				logger.error("getFENCEMappingForAllProjects: fence_mapping.json not found at "+JAXRSConfiguration.templatePath);
				return new ArrayList<Map>();
			}
		}
		
		
		String allProjectsJsonPath = "$.bio_data_catalyst[*]";
		
		Object projects = _parsed_fence_mapping.read(allProjectsJsonPath);

		if( ! (projects instanceof Collection) ) {
			//this should not happen
			logger.error("parsed json data does not contain any studies");
			return new ArrayList<Map>();
		}
		
		return (Collection)projects;
		
	}
}
