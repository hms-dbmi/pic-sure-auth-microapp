package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.hms.dbmi.avillach.auth.model.StudyMetaData;
import edu.harvard.hms.dbmi.avillach.auth.service.auth.FENCEAuthenticationService;
import edu.harvard.hms.dbmi.avillach.auth.utils.FenceMappingUtility;
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

    @Inject
    FENCEAuthenticationService fenceAuthenticationService;

    @Inject
    private FenceMappingUtility fenceMappingUtility;

    @ApiOperation(value = "POST a single study and it creates the role, privs, and rules for it, requires SUPER_ADMIN role")
    @Transactional
    @POST
    @RolesAllowed(SUPER_ADMIN)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/")
    public Response addStudyAccess(@ApiParam(value="The Study Identifier of the new study from the metadata.json") String studyIdentifier) {

        if (StringUtils.isBlank(studyIdentifier)) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Study identifier cannot be blank").build();
        }

        StudyMetaData fenceMappingForStudy;
        try {
            Map<String, StudyMetaData> fenceMapping = fenceMappingUtility.getFENCEMapping();
            if (fenceMapping == null) {
                throw new Exception("Fence mapping is null");
            }
            fenceMappingForStudy = fenceMapping.get(studyIdentifier);
        } catch(Exception ex) {
            logger.error(ex.toString());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error occurred while fetching FENCE mapping").build();
        }

        if (fenceMappingForStudy == null) {
            logger.error("addStudyAccess - Could not find study: {} in FENCE mapping", studyIdentifier);
            return Response.status(Response.Status.BAD_REQUEST).entity("Could not find study with the provided identifier").build();
        }

        String projectId = fenceMappingForStudy.getStudy_identifier();
        String consentCode = fenceMappingForStudy.getConsent_group_code();
        String newRoleName = StringUtils.isNotBlank(consentCode) ? MANUAL+projectId+"_"+consentCode : MANUAL+projectId;

        logger.debug("addStudyAccess - New manual PSAMA role name: {}", newRoleName);

        if (fenceAuthenticationService.upsertRole(null, newRoleName, MANUAL + " role "+newRoleName)) {
            logger.info("addStudyAccess - Updated user role. Now it includes `{}`", newRoleName);
             return Response.ok("Role '" + newRoleName + "' successfully created").build();
        } else {
            logger.error("addStudyAccess - could not add {} role to to database", newRoleName);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                           .entity("Could not add role '" + newRoleName + "' to database").build();
        }
    }
}