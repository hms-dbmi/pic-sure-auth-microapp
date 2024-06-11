package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication.FENCEAuthenticationService;
import edu.harvard.hms.dbmi.avillach.auth.utils.FenceMappingUtility;
import io.swagger.v3.oas.annotations.Parameter;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;
import java.util.Map;

@Service
public class StudyAccessService {
    private final Logger logger = LoggerFactory.getLogger(StudyAccessService.class);

    private final FenceMappingUtility fenceMappingUtility;
    private final RoleService roleService;

    public static final String MANUAL = "MANUAL_";
    public static final String STUDY_IDENTIFIER = "study_identifier";
    public static final String CONSENT_GROUP_CODE = "consent_group_code";

    @Autowired
    public StudyAccessService(FenceMappingUtility fenceMappingUtility, RoleService roleService) {
        this.fenceMappingUtility = fenceMappingUtility;
        this.roleService = roleService;
    }

    public String addStudyAccess(@Parameter(description="The Study Identifier of the new study from the metadata.json")
                                                @RequestBody String studyIdentifier) {
        if (StringUtils.isBlank(studyIdentifier)) {
            return "Error: Study identifier cannot be blank";
        }

        Map fenceMappingForStudy;
        try {
            Map<String, Map> fenceMapping = fenceMappingUtility.getFENCEMapping();
            if (fenceMapping == null) {
                throw new Exception("Fence mapping is null");
            }
            fenceMappingForStudy = fenceMapping.get(studyIdentifier);
        } catch(Exception ex) {
            logger.error(ex.toString());
            logger.error("addStudyAccess - Error occurred while fetching FENCE mapping");
            return "Error: occurred while fetching FENCE mapping";
        }

        if (fenceMappingForStudy == null || fenceMappingForStudy.isEmpty()) {
            logger.error("addStudyAccess - Could not find study: {} in FENCE mapping", studyIdentifier);
            return "Error: Could not find study with the provided identifier";
        }

        String projectId = (String) fenceMappingForStudy.get(STUDY_IDENTIFIER);
        String consentCode = (String) fenceMappingForStudy.get(CONSENT_GROUP_CODE);
        String newRoleName = StringUtils.isNotBlank(consentCode) ? MANUAL+projectId+"_"+consentCode : MANUAL+projectId;

        logger.debug("addStudyAccess - New manual PSAMA role name: {}", newRoleName);
        if (this.roleService.upsertFenceRole(null, newRoleName, MANUAL + " role "+newRoleName)) {
            logger.info("addStudyAccess - Updated user role. Now it includes `{}`", newRoleName);
            return "Role '" + newRoleName + "' successfully created";
        } else {
            logger.error("addStudyAccess - could not add {} role to to database", newRoleName);
            return "Error: Could not add role '" + newRoleName + "' to database";
        }
    }
}
