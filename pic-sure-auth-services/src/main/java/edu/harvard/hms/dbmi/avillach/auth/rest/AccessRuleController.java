package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.hms.dbmi.avillach.auth.entity.AccessRule;
import edu.harvard.hms.dbmi.avillach.auth.repository.AccessRuleRepository;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.BaseEntityService;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.transaction.Transactional;
import java.util.List;

import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.ADMIN;
import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.SUPER_ADMIN;

/**
 * <p>Endpoint for service handling business logic for access rules.</p>
 * <p>Note: Only users with the super admin role can access this endpoint.</p>
 *
 * Path: /accessRule
 */

@Controller("/accessRule")
public class AccessRuleController extends BaseEntityService<AccessRule> {

    private final AccessRuleRepository accessRuleRepo;

//    @Context
//    private SecurityContext securityContext;

    @Autowired
    public AccessRuleController(AccessRuleRepository accessRuleRepo) {
        super(AccessRule.class);
        this.accessRuleRepo = accessRuleRepo;
    }

    @ApiOperation(value = "GET information of one AccessRule with the UUID, requires ADMIN or SUPER_ADMIN role")
    @Secured(value = {ADMIN, SUPER_ADMIN})
    @GetMapping(value = "/{accessRuleId}")
    public ResponseEntity<?> getAccessRuleById(
            @ApiParam(value="The UUID of the accessRule to fetch information about")
            @PathParam("accessRuleId") String accessRuleId) {
        return getEntityById(accessRuleId,accessRuleRepo);
    }

    @ApiOperation(value = "GET a list of existing AccessRules, requires ADMIN or SUPER_ADMIN role")
    @Secured({ADMIN, SUPER_ADMIN})
    @GetMapping("")
    public ResponseEntity<?> getAccessRuleAll() {
        return getEntityAll(accessRuleRepo);
    }

    @ApiOperation(value = "POST a list of AccessRules, requires SUPER_ADMIN role")
    @POST
    @RolesAllowed(SUPER_ADMIN)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/")
    public ResponseEntity<?> addAccessRule(
            @ApiParam(required = true, value = "A list of AccessRule in JSON format")
            List<AccessRule> accessRules){
        accessRules.stream().forEach(accessRule -> {
            if (accessRule.getEvaluateOnlyByGates() == null)
                accessRule.setEvaluateOnlyByGates(false);

            if (accessRule.getCheckMapKeyOnly() == null)
                accessRule.setCheckMapKeyOnly(false);

            if (accessRule.getCheckMapNode() == null)
                accessRule.setCheckMapNode(false);

            if (accessRule.getGateAnyRelation() == null)
                accessRule.setGateAnyRelation(false);
        });
        return addEntity(accessRules, accessRuleRepo);
    }

    @ApiOperation(value = "Update a list of AccessRules, will only update the fields listed, requires SUPER_ADMIN role")
    @PUT
    @RolesAllowed(SUPER_ADMIN)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/")
    public ResponseEntity<?> updateAccessRule(
            @ApiParam(required = true, value = "A list of AccessRule with fields to be updated in JSON format")
            List<AccessRule> accessRules){
        return updateEntity(accessRules, accessRuleRepo);
    }

    @ApiOperation(value = "DELETE an AccessRule by Id only if the accessRule is not associated by others, requires SUPER_ADMIN role")
    @Transactional
    @DELETE
    @RolesAllowed(SUPER_ADMIN)
    @Path("/{accessRuleId}")
    public ResponseEntity<?> removeById(
            @ApiParam(required = true, value = "A valid accessRule Id")
            @PathParam("accessRuleId") final String accessRuleId) {
        return removeEntityById(accessRuleId, accessRuleRepo);
    }

    @ApiOperation(value = "GET all types listed for the rule in accessRule that could be used, requires SUPER_ADMIN role")
    @GET
    @RolesAllowed(SUPER_ADMIN)
    @Path("/allTypes")
    @Produces(MediaType.APPLICATION_JSON)
    public ResponseEntity<?> getAllTypes(){
        return PICSUREResponse.success(AccessRule.TypeNaming.getTypeNameMap());
    }

}
