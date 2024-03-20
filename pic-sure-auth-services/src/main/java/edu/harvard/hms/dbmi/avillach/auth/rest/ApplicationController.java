package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.ApplicationService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.transaction.Transactional;
import java.util.List;

import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.SUPER_ADMIN;

/**
 * <p>Endpoint for registering and administering applications.
 * <br>
 * Note: Only users with the super admin role can access this endpoint.</p>
 */
@Api
@Controller
@RequestMapping(value = "/application")
public class ApplicationController {

    private final ApplicationService applicationService;

    @Autowired
    public ApplicationController(ApplicationService applicationService) {
        this.applicationService = applicationService;
    }

    @ApiOperation(value = "GET information of one Application with the UUID, no role restrictions")
    @GetMapping(value = "/{applicationId}")
    public ResponseEntity<?> getApplicationById(
            @ApiParam(required = true, value = "The UUID of the application to fetch information about")
            @PathVariable("applicationId") String applicationId) {
        return applicationService.getEntityById(applicationId);
    }

    @ApiOperation(value = "GET a list of existing Applications, no role restrictions")
    @GetMapping
    public ResponseEntity<?> getApplicationAll() {
        return applicationService.getEntityAll();
    }

    @ApiOperation(value = "POST a list of Applications, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
    @PostMapping(value = "/", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> addApplication(
            @ApiParam(required = true, value = "A list of AccessRule in JSON format")
            List<Application> applications) {
        return applicationService.addNewApplications(applications);
    }

    @ApiOperation(value = "Update a list of Applications, will only update the fields listed, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
    @PutMapping(value = "/", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> updateApplication(
            @ApiParam(required = true, value = "A list of AccessRule with fields to be updated in JSON format")
            List<Application> applications) {
        return applicationService.updateApplications(applications);
    }

    @ApiOperation(value = "Refresh a token of an application by application Id, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
    @GetMapping(value = "/refreshToken/{applicationId}")
    public ResponseEntity<?> refreshApplicationToken(
            @ApiParam(required = true, value = "A valid application Id")
            @PathVariable("applicationId") String applicationId) {
        return applicationService.refreshApplicationToken(applicationId);
    }

    @ApiOperation(value = "DELETE an Application by Id only if the application is not associated by others, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
    @DeleteMapping(value = "/{applicationId}")
    public ResponseEntity<?> removeById(
            @ApiParam(required = true, value = "A valid accessRule Id")
            @PathVariable("applicationId") final String applicationId) {
        return applicationService.deleteApplicationById(applicationId);
    }

}
