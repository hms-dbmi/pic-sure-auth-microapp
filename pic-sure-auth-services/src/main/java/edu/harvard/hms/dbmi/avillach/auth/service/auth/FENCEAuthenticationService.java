package edu.harvard.hms.dbmi.avillach.auth.service.auth;

import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_consent_group_concept_path;
import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_topmed_consent_group_concept_path;
import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_harmonized_concept_path;
import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_harmonized_consent_group_concept_path;
import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_standard_access_rules;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.Response;

import org.apache.http.Header;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.hibernate.query.criteria.internal.predicate.IsEmptyPredicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;

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
    private JsonNode fenceMapping;
    
    

    
    private static final Map<String, String> topMedARTemplates = Map.of(
    		"CATEGORY_VARIANT_FILTERS", "$.query.variantInfoFilters[*].categoryVariantInfoFilters.*",
    		"NUMERIC_VARIANT_FILTERS",  "$.query.variantInfoFilters[*].numericVariantInfoFilters.*");
    
    
    //some default gate config
    private static final Map<String, String> clinicalConsentTemplate = Map.of(
    		"GATE_PARENT_STUDY_CONSENT", "$..categoryFilters.['"+fence_consent_group_concept_path+"']");
    
    private static final Map<String, String> harmonizedConsentTemplates = Map.of(
    		//TODO: actual harmonized consent field
    		"GATE_HARMONIZED_CONSENT",   "$..categoryFilters.['"+fence_harmonized_concept_path+"']");
    
    private static final Map<String, String> topMedConsentTemplates = Map.of(
    		//TODO: actual topmed consent field
    		"GATE_TOPMED_CONSENT",   "$..categoryFilters.['"+fence_topmed_consent_group_concept_path+"']");
    
    

    @PostConstruct
	public void initializeFenceService() {
		 picSureApp = applicationRepo.getUniqueResultByColumn("name", "PICSURE");
		 fenceConnection = connectionRepo.getUniqueResultByColumn("label", "FENCE");
		 fenceMapping = getFENCEMapping();
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
            logger.debug("getFENCEProfile() user profile structure:"+fence_user_profile.asText());
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

            // These two special access does not matter. We are not using it.
            if (access_role_name.equals("admin") || access_role_name.equals("parent")) {
                continue;
            }
            //TODO:  handle 'topmed' role
            
            
            
            logger.debug("getFENCEProfile() AccessRole:"+access_role_name);
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
        new_user.setEmail(node.get("email").asText());
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
                r.setPrivileges(addPrivileges(u, r));
                roleRepo.persist(r);
                logger.info("upsertRole() created new role");
            }
            u.getRoles().add(r);
            status = true;
        } catch (Exception ex) {
            logger.error("upsertRole() Could not inser/update role "+roleName+" to repo, because "+ex.getMessage());
        }


        logger.debug("upsertRole() finished");
        return status;
    }

    private Set<Privilege> addPrivileges(User u, Role r) {
        String roleName = r.getName();
        logger.info("addPrivileges() starting, adding privilege(s) to role "+roleName);

        String[] parts = roleName.split("_");
        String project_name = parts[1];
        String consent_group = parts[2];
        JsonNode projectMetadata = fenceMapping.get(project_name);
        
        if(projectMetadata.isNull() || projectMetadata.size() == 0 || projectMetadata.get("consent_group").isNull()) {
        	// TODO: Assign NO ACCESS privilege here
        	//... but then how do we clear that out if there's new metadata to fix it? (whole DB gets cleared! -nc)
        }
        
        //each role can have up to three privileges: Parent  |  Harmonized  | Topmed
        //harmonized has 2 ARs for parent + harminized and harmonized only
        //Topmed has up to four ARs for topmed / topmed + parent / topmed + harmonized / topmed + parent + harmonized
        Set<Privilege> privs = r.getPrivileges();
        if (privs == null) { privs = new HashSet<Privilege>();}

        logger.info("addPrivileges() This is a new privilege");
        
        String projectType = projectMetadata.get("project_type").asText();
        String concept_path = projectMetadata.get("concept_path").asText();
        Boolean isHarmonized = projectMetadata.get("isHarmonized").asBoolean();
        
        if(projectType != null && projectType.contains("G")) {
        	//insert genomic/topmed privs - this will also add rules for including harmonized & parent data if applicable
        	privs.add(upsertTopmedPrivilege(project_name, consent_group, concept_path, isHarmonized));
        }
        
        if(projectType != null && projectType.contains("P")) {
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

            String consent_concept_path = isHarmonized ? fence_harmonized_consent_group_concept_path : fence_consent_group_concept_path;
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
            priv.setQueryScope(conceptPath);

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
            		
                }
                accessrules.add(ar);
                
				//also add another rule for accessing only harmonized data
				ar = upsertConsentAccessRule(project_name, consent_group, "HARMONIZED_ONLY", fence_harmonized_consent_group_concept_path);
	                
	            //if this is a new rule, we need to populate it
	            if(ar.getGates().size() == 0) {
	            	ar.getGates().addAll(getGates(false, true, false));
	            	ar.getSubAccessRule().addAll(getPhenotypeSubRules(fence_harmonized_concept_path));
	            	ar.getSubAccessRule().addAll(getTopmedRestrictedSubRules());
	            }
	            accessrules.add(ar);
            } else {
            	// NO HARMONIZED DATA
            	//just need one AR for parent study
	            AccessRule ar = upsertConsentAccessRule(project_name, consent_group, "PARENT_HARMONIZED", fence_consent_group_concept_path);
	            
	            //if this is a new rule, we need to populate it
	            if(ar.getGates().size() == 0) {
	            	ar.getGates().addAll(getGates(true, false, false));
	            	ar.getSubAccessRule().addAll(getPhenotypeSubRules(conceptPath));
	            	ar.getSubAccessRule().addAll(getTopmedRestrictedSubRules());
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
        logger.debug("upsertTopmedRestrictedSubRule() starting");
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

        logger.debug("upsertTopmedRestrictedSubRule() finished");
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
    	//Categorical filters not included, because they will always have the consent values
    	rules.add(upsertPhenotypeSubRule("DISALLOW_NUMERIC", "$..numericFilters.[*]", AccessRule.TypeNaming.IS_EMPTY, "NUMERIC", false));
    	rules.add(upsertPhenotypeSubRule("DISALLOW_FIELDS", "$..fields.[*]", AccessRule.TypeNaming.IS_EMPTY, "FIELDS", false));
    	rules.add(upsertPhenotypeSubRule("DISALLOW_REQUIRED_FIELDS", "$..requiredFields.[*]", AccessRule.TypeNaming.IS_EMPTY, "REQUIRED_FIELDS", false));
    	
    	return rules;
	}

	private Collection<? extends AccessRule> getGates(boolean parent, boolean harmonized, boolean topmed) {
    	
    	 Set<AccessRule> gates = new HashSet<AccessRule>();
    	gates.add(upsertConsentGate("PARENT_CONSENT", "$..categoryFilters.['" + fence_consent_group_concept_path + "']", parent, "parent study data"));
    	gates.add(upsertConsentGate("HARMONIZED_CONSENT", "$..categoryFilters.['" + fence_harmonized_consent_group_concept_path + "']", harmonized, "harmonized data"));
    	gates.add(upsertConsentGate("TOPMED_CONSENT", "$..categoryFilters.['" + fence_topmed_consent_group_concept_path + "']", topmed, "Topmed data"));
   		
		return null;
	}
	
	 private AccessRule upsertPhenotypeSubRule(String conceptPath, String rule, int ruleType, String label, boolean useMapKey) {
	        logger.debug("upsertPhenotypeSubRule() starting");
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

	        logger.debug("upsertPhenotypeSubRule() finished");
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

            Set<AccessRule> accessrules = new HashSet<AccessRule>();
            
            AccessRule ar = upsertTopmedAccessRule(project_name, consent_group, "TOPMED");
            
            //if this is a new rule, we need to populate it
            if(ar.getGates().size() == 0) {
            	ar.getGates().addAll(getGates(false, false, true));
        		ar.getSubAccessRule().addAll(getPhenotypeRestrictedSubRules());
            }
            accessrules.add(ar);
            
            if(parentConceptPath != null) {
            	
            	ar = upsertTopmedAccessRule(project_name, consent_group, "TOPMED+PARENT");
                
                //if this is a new rule, we need to populate it
                if(ar.getGates().size() == 0) {
                	ar.getGates().addAll(getGates(true, false, true));
            		ar.getSubAccessRule().addAll(getPhenotypeSubRules(parentConceptPath));
            		ar.getSubAccessRule().add(upsertConsentAccessRule(project_name, consent_group, "PARENT_SUB_RULE", fence_consent_group_concept_path));
                }
                accessrules.add(ar);
                
                
                if(isHarmonized) {
                	//harmonized data has two ARs; one for adding _only_ harmonized, and one for a mix of harmonized and parent concepts
                	ar = upsertTopmedAccessRule(project_name, consent_group, "TOPMED+HARMONIZED");
                    
                    //if this is a new rule, we need to populate it
                    if(ar.getGates().size() == 0) {
                    	ar.getGates().addAll(getGates(true, true, false));
                		ar.getSubAccessRule().addAll(getPhenotypeSubRules(fence_harmonized_concept_path));
                		ar.getSubAccessRule().add(upsertConsentAccessRule(project_name, consent_group, "HARMONIZED_SUB_RULE", fence_harmonized_consent_group_concept_path));
                    }
                    
                    accessrules.add(ar);
                    
                    
                	ar = upsertTopmedAccessRule(project_name, consent_group, "TOPMED+HARMONIZED+PARENT");
                    
                    //if this is a new rule, we need to populate it
                    if(ar.getGates().size() == 0) {
                    	ar.getGates().addAll(getGates(true, true, false));
                    	ar.getSubAccessRule().addAll(getPhenotypeSubRules(parentConceptPath));
                		ar.getSubAccessRule().addAll(getPhenotypeSubRules(fence_harmonized_concept_path));
                		ar.getSubAccessRule().add(upsertConsentAccessRule(project_name, consent_group, "PARENT_SUB_RULE", fence_consent_group_concept_path));
                		ar.getSubAccessRule().add(upsertConsentAccessRule(project_name, consent_group, "HARMONIZED_SUB_RULE", fence_harmonized_consent_group_concept_path));
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
	        
		return gate;
	}
	

	/**
	 * Get the mappings of fence privileges
	 * 
	 * 
	 * 
	 * 
	 * 
	 */
	@SuppressWarnings("unchecked")
	
	private JsonNode getFENCEMapping() {
		try {
			return JAXRSConfiguration.objectMapper.readTree(new File(String.join(File.separator,
					new String[] {JAXRSConfiguration.templatePath ,"fence_mapping.json"})));
//			return JAXRSConfiguration.objectMapper.readValue(
//					new File(String.join(File.separator,
//							new String[] {JAXRSConfiguration.templatePath ,"fence_mapping.json"}))
//					, Map.class);
		} catch (IOException e) {
			logger.error("fence_mapping.json not found at "+JAXRSConfiguration.templatePath);
		}
		return new JsonNodeFactory(false).nullNode();
	}

}
