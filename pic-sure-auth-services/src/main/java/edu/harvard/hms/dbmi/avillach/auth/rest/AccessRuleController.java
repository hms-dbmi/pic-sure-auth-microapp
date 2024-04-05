package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.hms.dbmi.avillach.auth.entity.AccessRule;
import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.AccessRuleService;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.ADMIN;
import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.SUPER_ADMIN;

/**
 * <p>Endpoint for service handling business logic for access rules.</p>
 * <p>Note: Only users with the super admin role can access this endpoint.</p>
 * <p>
 * Path: /accessRule
 */

@Controller("/accessRule")
public class AccessRuleController {

    private final AccessRuleService accessRuleService;

    @Autowired
    public AccessRuleController(AccessRuleService accessRuleService) {
        this.accessRuleService = accessRuleService;
    }

    @ApiOperation(value = "GET information of one AccessRule with the UUID, requires ADMIN or SUPER_ADMIN role")
    @Secured(value = {ADMIN, SUPER_ADMIN})
    @GetMapping(value = "/{accessRuleId}")
    public ResponseEntity<?> getAccessRuleById(
            @ApiParam(value = "The UUID of the accessRule to fetch information about")
            @PathVariable("accessRuleId") String accessRuleId) {
        Optional<AccessRule> entityById = this.accessRuleService.getAccessRuleById(accessRuleId);

        if (entityById.isEmpty()) {
            return PICSUREResponse.error("AccessRule not found", 404);
        }

        return PICSUREResponse.success(entityById.get());
    }

    @ApiOperation(value = "GET a list of existing AccessRules, requires ADMIN or SUPER_ADMIN role")
    @Secured({ADMIN, SUPER_ADMIN})
    @GetMapping("")
    public ResponseEntity<?> getAccessRuleAll() {
        List<AccessRule> allAccessRules = this.accessRuleService.getAllAccessRules();
        return PICSUREResponse.success(allAccessRules);
    }

    @ApiOperation(value = "POST a list of AccessRules, requires SUPER_ADMIN role")
    @RolesAllowed(SUPER_ADMIN)
    @PostMapping(path = "/", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> addAccessRule(
            @ApiParam(required = true, value = "A list of AccessRule in JSON format")
            List<AccessRule> accessRules) {
        accessRules = this.accessRuleService.addAccessRule(accessRules);

        if (accessRules.isEmpty()) {
            return PICSUREResponse.protocolError("No access rules added", 400);
        }

        return PICSUREResponse.success(accessRules);
    }

    @ApiOperation(value = "Update a list of AccessRules, will only update the fields listed, requires SUPER_ADMIN role")
    @RolesAllowed(SUPER_ADMIN)
    @PutMapping(path = "/", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> updateAccessRule(
            @ApiParam(required = true, value = "A list of AccessRule with fields to be updated in JSON format")
            List<AccessRule> accessRules) {
        accessRules = this.accessRuleService.updateAccessRules(accessRules);
        return PICSUREResponse.success(accessRules);
    }

    @ApiOperation(value = "DELETE an AccessRule by Id only if the accessRule is not associated by others, requires SUPER_ADMIN role")
    @RolesAllowed(SUPER_ADMIN)
    @DeleteMapping(path = "/{accessRuleId}")
    public ResponseEntity<?> removeById(
            @ApiParam(required = true, value = "A valid accessRule Id")
            @PathVariable("accessRuleId") final String accessRuleId) {
        return PICSUREResponse.success(this.accessRuleService.removeAccessRuleById(accessRuleId));
    }

    @ApiOperation(value = "GET all types listed for the rule in accessRule that could be used, requires SUPER_ADMIN role")
    @RolesAllowed(SUPER_ADMIN)
    @GetMapping(path = "/allTypes", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getAllTypes() {
        return PICSUREResponse.success(AccessRule.TypeNaming.getTypeNameMap());
    }

}
