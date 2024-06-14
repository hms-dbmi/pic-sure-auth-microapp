package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.entity.AccessRule;
import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.entity.Role;
import edu.harvard.hms.dbmi.avillach.auth.model.fenceMapping.StudyMetaData;
import edu.harvard.hms.dbmi.avillach.auth.repository.PrivilegeRepository;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.authorization.AccessRuleService;
import edu.harvard.hms.dbmi.avillach.auth.utils.FenceMappingUtility;
import edu.harvard.hms.dbmi.avillach.auth.utils.StringUtils;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.ADMIN;

@Service
public class PrivilegeService {

    private final static Logger logger = LoggerFactory.getLogger(PrivilegeService.class.getName());

    private final PrivilegeRepository privilegeRepository;
    private final FenceMappingUtility fenceMappingUtility;
    private final AccessRuleService accessRuleService;
    private final ApplicationService applicationService;

    private Application picSureApp;

    private final String variantAnnotationColumns;
    private final String fence_harmonized_consent_group_concept_path;
    private final String fence_parent_consent_group_concept_path;
    private final String fence_topmed_consent_group_concept_path;
    private String fence_harmonized_concept_path; // This variable is modified so it cannot be final

    private static final String topmedAccessionField = "\\\\_Topmed Study Accession with Subject ID\\\\";

    @Autowired
    protected PrivilegeService(
            PrivilegeRepository privilegeRepository,
            FenceMappingUtility fenceMappingUtility,
            AccessRuleService accessRuleService,
            ApplicationService applicationService,
            @Value("${fence.variant.annotation.columns}") String variantAnnotationColumns,
            @Value("${fence.harmonized.consent.group.concept.path}") String fenceHarmonizedConsentGroupConceptPath,
            @Value("${fence.parent.consent.group.concept.path}") String fenceParentConceptPath,
            @Value("${fence.topmed.consent.group.concept.path}") String fenceTopmedConceptPath,
            @Value("${fence.consent.group.concept.path}") String fenceHarmonizedConceptPath) {
        this.privilegeRepository = privilegeRepository;
        this.fenceMappingUtility = fenceMappingUtility;
        this.accessRuleService = accessRuleService;
        this.applicationService = applicationService;
        this.variantAnnotationColumns = variantAnnotationColumns;
        this.fence_harmonized_consent_group_concept_path = fenceHarmonizedConsentGroupConceptPath;
        this.fence_parent_consent_group_concept_path = fenceParentConceptPath;
        this.fence_topmed_consent_group_concept_path = fenceTopmedConceptPath;
        this.fence_harmonized_concept_path = fenceHarmonizedConceptPath;
    }

    @PostConstruct
    public void init() {
        picSureApp = applicationService.getApplicationByName("PICSURE");

        logger.info("PrivilegeService is initializing...");
        logger.info("fence.variant.annotation.columns: {}", variantAnnotationColumns);
        logger.info("fence.harmonized.consent.group.concept.path: {}", fence_harmonized_consent_group_concept_path);
        logger.info("fence.parent.consent.group.concept.path: {}", fence_parent_consent_group_concept_path);
        logger.info("fence.topmed.consent.group.concept.path: {}", fence_topmed_consent_group_concept_path);
        logger.info("fence.consent.group.concept.path: {}", fence_harmonized_concept_path);
        logger.info("PrivilegeService is initialized.");
    }

    @Transactional
    public List<Privilege> deletePrivilegeByPrivilegeId(String privilegeId) {
        Optional<Privilege> privilege = this.privilegeRepository.findById(UUID.fromString(privilegeId));

        // Get security context with spring security context
        SecurityContext securityContext = SecurityContextHolder.getContext();
        // Get the principal name from the security context
        String principalName = securityContext.getAuthentication().getName();

        if (ADMIN.equals(privilege.get().getName()))  {
            logger.info("User: {}, is trying to remove the system admin privilege: " + ADMIN, principalName);
            throw new RuntimeException("System Admin privilege cannot be removed - uuid: " + privilege.get().getUuid().toString()
                    + ", name: " + privilege.get().getName());
        }

        this.privilegeRepository.deleteById(UUID.fromString(privilegeId));
        return this.getPrivilegesAll();
    }

    public List<Privilege> updatePrivileges(List<Privilege> privileges) {
        this.privilegeRepository.saveAll(privileges);
        return this.getPrivilegesAll();
    }

    public List<Privilege> addPrivileges(List<Privilege> privileges) {
        return this.privilegeRepository.saveAll(privileges);
    }

    public List<Privilege> getPrivilegesAll() {
        return this.privilegeRepository.findAll();
    }

    public Privilege getPrivilegeById(String privilegeId) {
        return this.privilegeRepository.findById(UUID.fromString(privilegeId)).orElse(null);
    }

    public Privilege findByName(String privilegeName) {
        return this.privilegeRepository.findByName(privilegeName);
    }

    public Privilege save(Privilege privilege) {
        return this.privilegeRepository.save(privilege);
    }

    public Set<Privilege> addFENCEPrivileges(Role r) {
        String roleName = r.getName();
        logger.info("addFENCEPrivileges() starting, adding privilege(s) to role {}", roleName);

        //each project can have up to three privileges: Parent  |  Harmonized  | Topmed
        //harmonized has 2 ARs for parent + harminized and harmonized only
        //Topmed has up to three ARs for topmed / topmed + parent / topmed + harmonized
        Set<Privilege> privs = r.getPrivileges();
        if (privs == null) { privs = new HashSet<Privilege>();}

        //e.g. FENCE_phs0000xx_c2 or FENCE_tutorial-biolinc_camp
        String project_name = StringUtils.extractProject(roleName);
        if (project_name.length() <= 0) {
            logger.warn("addFENCEPrivileges() role name: {} returned an empty project name", roleName);
        }
        String consent_group = StringUtils.extractConsentGroup(roleName);
        if (consent_group.length() <= 0) {
            logger.warn("addFENCEPrivileges() role name: {} returned an empty consent group", roleName);
        }
        logger.info("addFENCEPrivileges() project name: {} consent group: {}", project_name, consent_group);

        // Look up the metadata by consent group.
        StudyMetaData projectMetadata = this.fenceMappingUtility.getFENCEMappingforProjectAndConsent(project_name, consent_group);

        if(projectMetadata == null) {
            //no privileges means no access to this project.  just return existing set of privs.
            logger.warn("No metadata available for project {}.{}", project_name, consent_group);
            return privs;
        }

        logger.info("addPrivileges() This is a new privilege");

        String dataType = projectMetadata.getDataType();
        Boolean isHarmonized = projectMetadata.getIsHarmonized();
        String concept_path = projectMetadata.getTopLevelPath();
        String projectAlias = projectMetadata.getAbbreviatedName();

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

    /**
     * Creates a privilege for Topmed access. This has (up to) three access rules:
     * 1) topmed only 2) topmed + parent 3) topmed + harmonized.
     * @param studyIdentifier
     * @param projectAlias
     * @param consentGroup
     * @param parentConceptPath
     * @param isHarmonized
     * @return Privilege
     */
    private Privilege upsertTopmedPrivilege(String studyIdentifier, String projectAlias, String consentGroup, String parentConceptPath, boolean isHarmonized) {
        String privilegeName = "PRIV_FENCE_" + studyIdentifier + "_" + consentGroup + "_TOPMED";
        Privilege priv = findByName(privilegeName);

        if (priv != null) {
            logger.info("upsertTopmedPrivilege() {} already exists", privilegeName);
            return priv;
        }

        priv = new Privilege();

        try {
            buildPrivilegeObject(priv, privilegeName, studyIdentifier, consentGroup);

            Set<AccessRule> accessRules = new HashSet<>();
            AccessRule topmedRule = this.accessRuleService.upsertTopmedAccessRule(studyIdentifier, consentGroup, "TOPMED");

            this.accessRuleService.populateAccessRule(topmedRule, false, false, true);
            topmedRule.getSubAccessRule().addAll(this.accessRuleService.getPhenotypeRestrictedSubRules(studyIdentifier, consentGroup, projectAlias));
            accessRules.add(topmedRule);

            if (parentConceptPath != null) {
                AccessRule topmedParentRule = this.accessRuleService.upsertTopmedAccessRule(studyIdentifier, consentGroup, "TOPMED+PARENT");
                this.accessRuleService.populateAccessRule(topmedParentRule, true, false, true);
                topmedParentRule.getSubAccessRule().addAll(this.accessRuleService.getPhenotypeSubRules(studyIdentifier, parentConceptPath, projectAlias));
                accessRules.add(topmedParentRule);

                if (isHarmonized) {
                    AccessRule harmonizedRule = this.accessRuleService.upsertHarmonizedAccessRule(studyIdentifier, consentGroup, "HARMONIZED");
                    this.accessRuleService.populateHarmonizedAccessRule(harmonizedRule, parentConceptPath, studyIdentifier, projectAlias);
                    accessRules.add(harmonizedRule);
                }
            }

            this.accessRuleService.addStandardAccessRules(accessRules);

            priv.setAccessRules(accessRules);
            logger.info("upsertTopmedPrivilege() Added {} access_rules to privilege", accessRules.size());

            privilegeRepository.save(priv);
            logger.info("upsertTopmedPrivilege() Added new privilege {} to DB", priv.getName());
        } catch (Exception ex) {
            logger.error("upsertTopmedPrivilege() could not save privilege", ex);
        }

        return priv;
    }

    private void buildPrivilegeObject(Privilege priv, String privilegeName, String studyIdentifier, String consentGroup) {
        priv.setApplication(picSureApp);
        priv.setName(privilegeName);
        priv.setDescription("FENCE privilege for Topmed " + studyIdentifier + "." + consentGroup);

        String consentConceptPath = escapePath(fence_topmed_consent_group_concept_path);
        fence_harmonized_concept_path = escapePath(fence_harmonized_concept_path);

        String queryTemplateText = "{\"categoryFilters\": {\"" + consentConceptPath + "\":[\"" + studyIdentifier + "." + consentGroup + "\"]},"
                + "\"numericFilters\":{},\"requiredFields\":[],"
                + "\"fields\":[\"" + topmedAccessionField + "\"],"
                + "\"variantInfoFilters\":[{\"categoryVariantInfoFilters\":{},\"numericVariantInfoFilters\":{}}],"
                + "\"expectedResultType\": \"COUNT\""
                + "}";

        priv.setQueryTemplate(queryTemplateText);

        priv.setQueryScope(buildQueryScope(this.variantAnnotationColumns));
    }

    /**
     * Creates a privilege with a set of access rules that allow queries containing a consent group to pass if the query only contains valid entries that match conceptPath.  If the study is harmonized,
     * this also creates an access rule to allow access when using the harmonized consent concept path.
     * Privileges created with this method will deny access if any genomic filters (topmed data) are included.
     *
     * @param studyIdentifier The study identifier
     * @param consent_group The consent group
     * @param conceptPath The concept path
     * @param isHarmonized Whether the study is harmonized
     * @return The created privilege
     */
    private Privilege upsertClinicalPrivilege(String studyIdentifier, String projectAlias, String consent_group, String conceptPath, boolean isHarmonized) {
        // Construct the privilege name
        String privilegeName = (consent_group != null && !consent_group.isEmpty()) ?
                "PRIV_FENCE_" + studyIdentifier + "_" + consent_group + (isHarmonized ? "_HARMONIZED" : "") :
                "PRIV_FENCE_" + studyIdentifier + (isHarmonized ? "_HARMONIZED" : "");

        // Check if the Privilege already exists
        Privilege priv = findByName(privilegeName);
        if (priv != null) {
            logger.info("{} already exists", privilegeName);
            return priv;
        }

        priv = new Privilege();
        try {
            priv.setApplication(picSureApp);
            priv.setName(privilegeName);

            // Set consent concept path
            String consent_concept_path = isHarmonized ? fence_harmonized_consent_group_concept_path : fence_parent_consent_group_concept_path;
            if (!consent_concept_path.contains("\\\\")) {
                consent_concept_path = consent_concept_path.replaceAll("\\\\", "\\\\\\\\");
                logger.debug("Escaped consent concept path: {}", consent_concept_path);
            }

            if(fence_harmonized_concept_path != null && !fence_harmonized_concept_path.contains("\\\\")){
                //these have to be escaped again so that jaxson can convert it correctly
                fence_harmonized_concept_path = fence_harmonized_concept_path.replaceAll("\\\\", "\\\\\\\\");
                logger.debug("upsertTopmedPrivilege(): escaped harmonized consent path" + fence_harmonized_concept_path);
            }


            String studyIdentifierField = (consent_group != null && !consent_group.isEmpty()) ? studyIdentifier + "." + consent_group : studyIdentifier;
            String queryTemplateText = String.format(
                    "{\"categoryFilters\": {\"%s\":[\"%s\"]},\"numericFilters\":{},\"requiredFields\":[],\"fields\":[],\"variantInfoFilters\":[{\"categoryVariantInfoFilters\":{},\"numericVariantInfoFilters\":{}}],\"expectedResultType\": \"COUNT\"}",
                    consent_concept_path, studyIdentifierField
            );

            priv.setQueryTemplate(queryTemplateText);
            priv.setQueryScope(isHarmonized ? String.format("[\"%s\",\"_\",\"%s\"]", conceptPath, fence_harmonized_concept_path) : String.format("[\"%s\",\"_\"]", conceptPath));

            // Initialize the set of AccessRules
            Set<AccessRule> accessrules = new HashSet<>();

            // Create and add the parent consent access rule
            AccessRule ar = this.accessRuleService.createConsentAccessRule(studyIdentifier, consent_group, "PARENT", fence_parent_consent_group_concept_path);
            this.accessRuleService.configureAccessRule(ar, studyIdentifier, consent_group, conceptPath, projectAlias, true, false, false);
            accessrules.add(ar);

            // Create and add the Topmed+Parent access rule
            ar = this.accessRuleService.upsertTopmedAccessRule(studyIdentifier, consent_group, "TOPMED+PARENT");
            this.accessRuleService.configureAccessRule(ar, studyIdentifier, consent_group, conceptPath, projectAlias, true, false, true);
            accessrules.add(ar);

            // If harmonized, create and add the harmonized access rule
            if (isHarmonized) {
                ar = this.accessRuleService.createConsentAccessRule(studyIdentifier, consent_group, "HARMONIZED", fence_harmonized_consent_group_concept_path);
                this.accessRuleService.configureHarmonizedAccessRule(ar, studyIdentifier, consent_group, conceptPath, projectAlias);
                accessrules.add(ar);
            }

            // Add standard access rules
            this.accessRuleService.addStandardAccessRules(accessrules);

            priv.setAccessRules(accessrules);
            logger.info("Added {} access_rules to privilege", accessrules.size());

            privilegeRepository.save(priv);
            logger.info("Added new privilege {} to DB", priv.getName());
        } catch (Exception ex) {
            logger.error("Could not save privilege", ex);
        }
        return priv;
    }

    private String escapePath(String path) {
        if (path != null && !path.contains("\\\\")) {
            return path.replaceAll("\\\\", "\\\\\\\\");
        }
        return path;
    }

    private String buildQueryScope(String variantColumns) {
        if (variantColumns == null || variantColumns.isEmpty()) {
            return "[\"_\"]";
        }

        return Arrays.stream(variantColumns.split(","))
                .map(path -> "\"" + path + "\"")
                .collect(Collectors.joining(",", "[", ",\"_\"]"));
    }

    public Optional<Privilege> findById(UUID uuid) {
        return this.privilegeRepository.findById(uuid);
    }
}
