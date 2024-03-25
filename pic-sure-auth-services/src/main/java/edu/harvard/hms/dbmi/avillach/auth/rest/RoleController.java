package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.hms.dbmi.avillach.auth.entity.Role;
import edu.harvard.hms.dbmi.avillach.auth.service.RoleService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.ADMIN;
import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.SUPER_ADMIN;

/**
 * <p>Endpoint for service handling business logic for user roles.
 * <br>Note: Users with admin level access can view roles, but only super admin users can modify them.</p>
 */
@Api
@Controller
@RequestMapping(value = "/role")
public class RoleController {

    private final RoleService roleService;

    @Autowired
    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    @ApiOperation(value = "GET information of one Role with the UUID, requires ADMIN or SUPER_ADMIN role")
    @RolesAllowed({ADMIN, SUPER_ADMIN})
    @GetMapping(produces = "application/json", path = "/{roleId}")
    public ResponseEntity<?> getRoleById(
            @ApiParam(value="The UUID of the Role to fetch information about")
            @PathVariable("roleId") String roleId) {
        return this.roleService.getEntityById(roleId);
    }

    @ApiOperation(value = "GET a list of existing Roles, requires ADMIN or SUPER_ADMIN role")
    @GetMapping(produces = "application/json")
    @RolesAllowed({ADMIN, SUPER_ADMIN})
    public ResponseEntity<?> getRoleAll() {
        return this.roleService.getEntityAll();
    }

    @ApiOperation(value = "POST a list of Roles, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
    @PostMapping(produces = "application/json")
    public ResponseEntity<?> addRole(
            @ApiParam(required = true, value = "A list of Roles in JSON format")
            List<Role> roles){
        return this.roleService.addEntity(roles);
    }

    @ApiOperation(value = "Update a list of Roles, will only update the fields listed, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
    @PutMapping(produces = "application/json")
    public ResponseEntity<?> updateRole(
            @ApiParam(required = true, value = "A list of Roles with fields to be updated in JSON format")
            List<Role> roles){
        return this.roleService.updateEntity(roles);
    }

    @ApiOperation(value = "DELETE an Role by Id only if the Role is not associated by others, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
    @DeleteMapping(produces = "application/json", path = "/{roleId}")
    public ResponseEntity<?> removeById(
            @ApiParam(required = true, value = "A valid Role Id")
            @PathVariable("roleId") final String roleId) {
        return this.roleService.removeEntityById(roleId);
    }



}
