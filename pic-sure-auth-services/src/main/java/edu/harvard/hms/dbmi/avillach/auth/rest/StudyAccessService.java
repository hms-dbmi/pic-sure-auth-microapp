package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.hms.dbmi.avillach.auth.data.entity.Role;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.RoleRepository;
import edu.harvard.hms.dbmi.avillach.auth.service.auth.FENCEAuthenticationService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.transaction.Transactional;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.util.Map;

import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.SUPER_ADMIN;

/**
 * <p>Endpoint for service handling business logic for adding all the auth
 * rules for a given study</p>
 * <p>Note: Only users with the super admin role can access this endpoint.</p>
 */
@Api
@Path("/studyAccess")
public class StudyAccessService {
    Logger logger = LoggerFactory.getLogger(StudyAccessService.class);

    public static final String MANUAL = "MANUAL_";
    public static final String STUDY_IDENTIFIER = "study_identifier";
    public static final String CONSENT_GROUP_CODE = "consent_group_code";

    @Inject
    FENCEAuthenticationService fenceAuthenticationService;

    @ApiOperation(value = "POST a single study and it creates the role, privs, and rules for it, requires SUPER_ADMIN role")
    @Transactional
    @POST
    @RolesAllowed(SUPER_ADMIN)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/")
    public Response addStudyAccess(@ApiParam(value="The Study Identifier of the new study from the metadata.json") String studyIdentifier) {
        if (StringUtils.isBlank(studyIdentifier)) {
            return Response.status(Response.Status.BAD_REQUEST)
                       .entity("Study identifier cannot be blank")
                       .build();
        }
        Map fenceMappingForStudy = null;
        try {
            Map<String, Map> fenceMapping = fenceAuthenticationService.getFENCEMapping();
            if (fenceMapping == null) {
                throw new Exception("Fence mapping is null");
            }
            fenceMappingForStudy = fenceMapping.get(studyIdentifier);
        } catch(Exception ex) {
            logger.error(ex.toString());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                       .entity("Error occurred while fetching FENCE mapping")
                       .build();
        }
        if (fenceMappingForStudy == null || fenceMappingForStudy.isEmpty()) {
            logger.error("addStudyAccess - Could not find study: " + studyIdentifier + " in FENCE mapping");
            return Response.status(Response.Status.BAD_REQUEST)
                       .entity("Could not find study with the provided identifier")
                       .build();
        }
        String projectId = (String) fenceMappingForStudy.get(STUDY_IDENTIFIER);
        String consentCode = (String) fenceMappingForStudy.get(CONSENT_GROUP_CODE);
        String newRoleName = StringUtils.isNotBlank(consentCode) ? MANUAL+projectId+"_"+consentCode : MANUAL+projectId;

        logger.debug("addStudyAccess - New manual PSAMA role name: "+newRoleName);

        if (fenceAuthenticationService.upsertRole(null, newRoleName, MANUAL + " role "+newRoleName)) {
            logger.info("addStudyAccess - Updated user role. Now it includes `"+newRoleName+"`");
             return Response.ok("Role '" + newRoleName + "' successfully created").build();
        } else {
            logger.error("addStudyAccess - could not add " + newRoleName + " role to to database");
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                   .entity("Could not add role '" + newRoleName + "' to database")
                   .build();
        }
    }
}
