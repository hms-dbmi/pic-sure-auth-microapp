package edu.harvard.hms.dbmi.avillach.auth.service.auth;

import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_consent_group_concept_path;
import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_topmed_consent_group_concept_path;
import static edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration.fence_harmonized_concept_path;
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
    
    
    //some default gate config
    private static final Map<String, String> clinicalGateMapTemplates = Map.of(
    		"CATEGORY_CLINICAL_FILTERS", "$.query.categoryFilters",
    		"NUMERIC_CLINICAL_FILTERS",  "$.query.numericFilters");
    
    private static final Map<String, String> clinicalGateListTemplates = Map.of(
    		"REQUIRED_FIELDS_FILTERS",  "$.query.requiredFields");
    
    private static final Map<String, String> topMedGateTemplates = Map.of(
    		"CATEGORY_VARIANT_FILTERS", "$.query.variantInfoFilters[*].categoryVariantInfoFilters.*",
    		"NUMERIC_VARIANT_FILTERS",  "$.query.variantInfoFilters[*].numericVariantInfoFilters.*");
    

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
                r.setPrivileges(upsertPrivilege(u, r));
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

    private Set<Privilege> upsertPrivilege(User u, Role r) {
        String roleName = r.getName();
        logger.info("upsertPrivilege() starting, adding privilege to role "+roleName);

        String[] parts = roleName.split("_");
        String project_name = parts[1];
        String consent_group = parts[2];
        JsonNode projectMetadata = fenceMapping.get(project_name);
        
        if(projectMetadata.isNull() || projectMetadata.size() == 0 || projectMetadata.get("consent_group").isNull()) {
        	// TODO: Assign NO ACCESS privilege here
        	//... but then how do we clear that out if there's new metadata to fix it?
        }
        
                

        // Get privilege and assign it to this role.
        String privilegeName = r.getName().replaceFirst("FENCE_*","PRIV_FENCE_");
        logger.info("upsertPrivilege() Looking for privilege, with name : "+privilegeName);

        Set<Privilege> privs = r.getPrivileges();
        if (privs == null) { privs = new HashSet<Privilege>();}

        Privilege p = privilegeRepo.getUniqueResultByColumn("name", privilegeName);
        if (p != null) {
            logger.info("upsertPrivilege() Assigning privilege "+p.getName()+" to role "+r.getName());
            privs.add(p);

        } else {
            logger.info("upsertPrivilege() This is a new privilege");
            
            String projectType = projectMetadata.get("project_type").asText();
            if(projectType != null && projectType.contains("G")) {
            	//insert genomic/topmed privs
            	privs.add(createNewTopmedPrivilege(project_name, consent_group));
            }
            
            if(projectType != null && projectType.contains("C")) {
            	//insert clinical privs
            	String concept_path = projectMetadata.get("concept_path").asText();
                logger.info("upsertPrivilege() project:"+project_name+" consent_group:"+consent_group+" concept_path:"+concept_path);

                // Add new privilege PRIV_FENCE_phs######_c# and PRIV_FENCE_phs######_c#_HARMONIZED
                privs.add(createNewClinicalPrivilege(project_name, consent_group, concept_path, false));
                privs.add(createNewClinicalPrivilege(project_name, consent_group, fence_harmonized_concept_path, true));
            	
            }
        }
        logger.info("upsertPrivilege() Finished");
        return privs;
    }

    private Privilege createNewClinicalPrivilege(String project_name, String consent_group, String queryScopeConceptPath, boolean isHarmonized) {
        Privilege priv = new Privilege();

        // Build Privilege Object
        try {
            priv.setApplication(picSureApp);
            priv.setName("PRIV_FENCE_"+project_name+"_"+consent_group+(isHarmonized?"_HARMONIZED":""));
            priv.setDescription("FENCE privilege for "+project_name+"/"+consent_group);

            String consent_concept_path = fence_consent_group_concept_path;
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
            priv.setQueryScope(queryScopeConceptPath);

            AccessRule ar = upsertClinicalAccessRule(project_name, consent_group, queryScopeConceptPath);
            if (ar != null) {
                Set<AccessRule> accessrules = new HashSet<AccessRule>();
                accessrules.add(ar);
                // Add additional access rules;  
                for(String arName: fence_standard_access_rules.split(",")) {
                    if (arName.startsWith("AR_")) {
                        logger.info("Adding AccessRule "+arName+" to privilege "+priv.getName());
                        accessrules.add(accessruleRepo.getUniqueResultByColumn("name",arName));
                    }
                }
                priv.setAccessRules(accessrules);
                logger.info("createNewPrivilege() Added "+accessrules.size()+" access_rules to privilege");
            }

            privilegeRepo.persist(priv);
            logger.info("createNewPrivilege() Added new privilege "+priv.getName()+" to DB");
        } catch (Exception ex) {
            ex.printStackTrace();
            logger.error("createNewPrivilege() could not save privilege");
        }
        return priv;
    }
    
    private Privilege createNewTopmedPrivilege(String project_name, String consent_group) {
        Privilege priv = new Privilege();

        // Build Privilege Object
        try {
            priv.setApplication(picSureApp);
            priv.setDescription("FENCE privilege for "+project_name+"/"+consent_group);
//            priv.setQueryScope();

            String consent_concept_path = fence_consent_group_concept_path;
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

            AccessRule ar = upsertTopmedAccessRule(project_name, consent_group);
            if (ar != null) {
                Set<AccessRule> accessrules = new HashSet<AccessRule>();
                accessrules.add(ar);
                // Add additional access rules;  
                for(String arName: fence_standard_access_rules.split(",")) {
                    if (arName.startsWith("AR_")) {
                        logger.info("Adding AccessRule "+arName+" to privilege "+priv.getName());
                        accessrules.add(accessruleRepo.getUniqueResultByColumn("name",arName));
                    }
                }
                priv.setAccessRules(accessrules);
                logger.info("createNewPrivilege() Added "+accessrules.size()+" access_rules to privilege");
            }

            privilegeRepo.persist(priv);
            logger.info("createNewPrivilege() Added new privilege "+priv.getName()+" to DB");
        } catch (Exception ex) {
            ex.printStackTrace();
            logger.error("createNewPrivilege() could not save privilege");
        }
        return priv;
    }

    private AccessRule upsertClinicalAccessRule(String project_name, String consent_group, String queryScopeConceptPath) {
        logger.debug("upsertClinicalAccessRule() starting");
        String ar_name = "AR_CLINICAL_"+project_name+"_"+consent_group;
        AccessRule ar = accessruleRepo.getUniqueResultByColumn("name", ar_name);
        if (ar != null) {
            logger.info("upsertClinicalAccessRule() AccessRule "+ar_name+" already exists.");
            return ar;
        }

        logger.info("upsertClinicalAccessRule() Creating new access rule "+ar_name);
        ar = new AccessRule();
        ar.setName(ar_name);
        ar.setDescription("FENCE AR for "+project_name+"/"+consent_group + " clinical concepts");
        StringBuilder ruleText = new StringBuilder();
        ruleText.append("$..categoryFilters.['");
        ruleText.append(fence_consent_group_concept_path);
        ruleText.append("']");
        ar.setRule(ruleText.toString());
        ar.setType(AccessRule.TypeNaming.ALL_EQUALS);
        ar.setValue(project_name+"."+consent_group);
        ar.setCheckMapKeyOnly(false);
        ar.setCheckMapNode(true);
        ar.setEvaluateOnlyByGates(false);
        ar.setGateAnyRelation(true);  //one gate per 'categoryFilter/NumericFilter etc.'. one non-null value triggers.

        // Assign all GATE_ access rules to this AR access rule.
        Set<AccessRule> gates = new HashSet<AccessRule>();
        
        //category & numeric paths are objects; req. fields is a list
        for (Entry<String, String> gateTemplate : clinicalGateMapTemplates.entrySet()) {
        	gates.add(upsertClinicalGate(project_name, queryScopeConceptPath, gateTemplate.getKey(), gateTemplate.getValue(), true));
		}
        
        for (Entry<String, String> gateTemplate : clinicalGateListTemplates.entrySet()) {
        	gates.add(upsertClinicalGate(project_name, queryScopeConceptPath, gateTemplate.getKey(), gateTemplate.getValue(), false));
		}
        
        ar.setGates(gates);

        accessruleRepo.persist(ar);

        logger.debug("upsertAccessRule() finished");
        return ar;
    }
    
    private AccessRule upsertTopmedAccessRule(String project_name, String consent_group) {
        logger.debug("upsertTopmedAccessRule() starting");
        String ar_name = "AR_TOPMED_"+project_name+"_"+consent_group;
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
        ar.setCheckMapNode(true);
        ar.setEvaluateOnlyByGates(false);
        ar.setGateAnyRelation(true);  //one gate per 'categoryFilter/NumericFilter etc.'. one non-null value triggers.

        // Assign all GATE_ access rules to this AR access rule.
        Set<AccessRule> gates = new HashSet<AccessRule>();
        
        //category & numeric paths are objects; req. fields is a list
        for (Entry<String, String> gateTemplate : topMedGateTemplates.entrySet()) {
        	gates.add(upsertTopmedGate(project_name, gateTemplate.getKey(), gateTemplate.getValue()));
		}
        //TODO: probably need to add another gate for VCF* result types; make sure there are no exports without filters.
        
        ar.setGates(gates);

        accessruleRepo.persist(ar);

        logger.debug("upsertAccessRule() finished");
        return ar;
    }

    /**
     * Insert a new gate if it doesn't exist yet.  
     * return an existing gate named GATE_{project_name_}_{gate_name_template} if it exists.
     */
	private AccessRule upsertClinicalGate(String project_name, String queryScopeConceptPath, String gate_name_template, String rule,
			boolean checkMapNode) {
		
		 String gate_name = "GATE_" + project_name + "_" + gate_name_template;
		
		 AccessRule gate = accessruleRepo.getUniqueResultByColumn("name", gate_name);
	        if (gate != null) {
	            logger.info("upsertClinicalGate() AccessRule "+gate_name+" already exists.");
	            return gate;
	        }

	        logger.info("upsertClinicalGate() Creating new access rule "+gate_name);
	        gate = new AccessRule();
	        gate.setName(gate_name);
	        gate.setDescription("FENCE GATE for "+project_name+" "+gate_name_template);
	        gate.setRule(rule);
	        gate.setType(AccessRule.TypeNaming.ANY_EQUALS);
	        gate.setValue(queryScopeConceptPath);  //TODO: do we need to sanitize this at all?
	        gate.setCheckMapKeyOnly(checkMapNode); //trigger on the concept path for a study;  that's the map key.
	        gate.setCheckMapNode(checkMapNode);
	        gate.setEvaluateOnlyByGates(false);
	        gate.setGateAnyRelation(false); 
	        
		return gate;
	}
	
	/**
	 * For topmed/genomic data we don't need to have a separate gate for each project;  they all share the same concept
	 * paths.  We just trigger on a non-empty value in the variant filters.
	 * 
	 * @param project_name
	 * @param gate_name_template
	 * @param rule
	 * @return
	 */
	private AccessRule upsertTopmedGate(String project_name, String gate_name_template, String rule) {
		
		 String gate_name = "GATE_" + gate_name_template;
		
		 AccessRule gate = accessruleRepo.getUniqueResultByColumn("name", gate_name);
	        if (gate != null) {
	            logger.info("upsertTopmedGate() AccessRule "+gate_name+" already exists.");
	            return gate;
	        }

	        logger.info("upsertTopmedGate() Creating new access rule "+gate_name);
	        gate = new AccessRule();
	        gate.setName(gate_name);
	        gate.setDescription("FENCE GATE for "+project_name+" "+gate_name_template);
	        gate.setRule(rule);
	        gate.setType(AccessRule.TypeNaming.IS_NOT_EMPTY);
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
