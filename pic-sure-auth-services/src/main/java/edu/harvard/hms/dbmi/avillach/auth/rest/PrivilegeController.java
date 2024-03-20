package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.service.PrivilegeService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.ADMIN;
import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.SUPER_ADMIN;

/**
 * <p>Endpoint for service handling business logic for privileges.
 * <br>Note: Only users with the super admin role can access this endpoint.</p>
 */
@Api
@RestController
@RequestMapping("/privilege")
public class PrivilegeController {

    private final PrivilegeService privilegeService;

    @Autowired
    public PrivilegeController(PrivilegeService privilegeService) {
        this.privilegeService = privilegeService;
    }

    @ApiOperation(value = "GET information of one Privilege with the UUID, requires ADMIN or SUPER_ADMIN role")
    @RolesAllowed({ADMIN, SUPER_ADMIN})
    @GetMapping(path = "/{privilegeId}", produces = "application/json")
    public ResponseEntity<?> getPrivilegeById(
            @ApiParam(value="The UUID of the privilege to fetch information about")
            @PathVariable("privilegeId") String privilegeId) {
        return this.privilegeService.getEntityById(privilegeId);
    }

    @ApiOperation(value = "GET a list of existing privileges, requires ADMIN or SUPER_ADMIN role")
    @RolesAllowed({ADMIN, SUPER_ADMIN})
    @GetMapping(path = "/", produces = "application/json")
    public ResponseEntity<?> getPrivilegeAll() {
        return this.privilegeService.getEntityAll();
    }

    @ApiOperation(value = "POST a list of privileges, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
    @PostMapping(path = "/", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> addPrivilege(
            @ApiParam(required = true, value = "A list of privileges in JSON format")
            List<Privilege> privileges){
        return this.privilegeService.addEntity(privileges);
    }

    @ApiOperation(value = "Update a list of privileges, will only update the fields listed, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
    @PutMapping(path = "/", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> updatePrivilege(
            @ApiParam(required = true, value = "A list of privilege with fields to be updated in JSON format")
            List<Privilege> privileges){
        return this.privilegeService.updateEntity(privileges);
    }

    @ApiOperation(value = "DELETE an privilege by Id only if the privilege is not associated by others, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
    @DeleteMapping(path = "/{privilegeId}", produces = "application/json")
    public ResponseEntity<?> removeById(
            @ApiParam(required = true, value = "A valid privilege Id")
            @PathVariable("privilegeId") final String privilegeId) {
        return this.privilegeService.deletePrivilegeByPrivilegeId(privilegeId);
    }

}
