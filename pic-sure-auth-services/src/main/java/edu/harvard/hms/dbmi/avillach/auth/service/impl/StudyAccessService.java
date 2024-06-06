package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication.FENCEAuthenticationService;
import edu.harvard.hms.dbmi.avillach.auth.utils.FenceMappingUtility;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Map;

import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.SUPER_ADMIN;

/**
 * <p>Endpoint for service handling business logic for adding all the auth
 * rules for a given study</p>
 * <p>Note: Only users with the super admin role can access this endpoint.</p>
 */
@Tag(name = "Study Access")
@Controller
@RequestMapping("/studyAccess")
public class StudyAccessService {
    private final FenceMappingUtility fenceMappingUtility;
    Logger logger = LoggerFactory.getLogger(StudyAccessService.class);

    public static final String MANUAL = "MANUAL_";
    public static final String STUDY_IDENTIFIER = "study_identifier";
    public static final String CONSENT_GROUP_CODE = "consent_group_code";

    private final FENCEAuthenticationService fenceAuthenticationService;

    @Autowired
    public StudyAccessService(FENCEAuthenticationService fenceAuthenticationService, FenceMappingUtility fenceMappingUtility) {
        this.fenceAuthenticationService = fenceAuthenticationService;
        this.fenceMappingUtility = fenceMappingUtility;
    }

    @Operation(description = "POST a single study and it creates the role, privs, and rules for it, requires SUPER_ADMIN role")
    @Transactional
    @PostMapping(consumes = "application/json")
    @Secured(SUPER_ADMIN)
    public ResponseEntity<?> addStudyAccess(@Parameter(description="The Study Identifier of the new study from the metadata.json")
                                                @RequestBody String studyIdentifier) {

        if (StringUtils.isBlank(studyIdentifier)) {
            return PICSUREResponse.error("Study identifier cannot be blank");
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
            return PICSUREResponse.error("Error occurred while fetching FENCE mapping");
        }

        if (fenceMappingForStudy == null || fenceMappingForStudy.isEmpty()) {
            logger.error("addStudyAccess - Could not find study: {} in FENCE mapping", studyIdentifier);
            return PICSUREResponse.error("Could not find study with the provided identifier");
        }

        String projectId = (String) fenceMappingForStudy.get(STUDY_IDENTIFIER);
        String consentCode = (String) fenceMappingForStudy.get(CONSENT_GROUP_CODE);
        String newRoleName = StringUtils.isNotBlank(consentCode) ? MANUAL+projectId+"_"+consentCode : MANUAL+projectId;

        logger.debug("addStudyAccess - New manual PSAMA role name: {}", newRoleName);

        if (fenceAuthenticationService.upsertRole(null, newRoleName, MANUAL + " role "+newRoleName)) {
            logger.info("addStudyAccess - Updated user role. Now it includes `{}`", newRoleName);
             return PICSUREResponse.success("Role '" + newRoleName + "' successfully created");
        } else {
            logger.error("addStudyAccess - could not add {} role to to database", newRoleName);
            return PICSUREResponse.error("Could not add role '" + newRoleName + "' to database");
        }
    }
}
