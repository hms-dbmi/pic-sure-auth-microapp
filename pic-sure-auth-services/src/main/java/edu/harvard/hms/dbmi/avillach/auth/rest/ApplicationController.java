package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.ApplicationService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

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
        Optional<Application> entityById = applicationService.getApplicationByID(applicationId);

        if (entityById.isEmpty()) {
            return PICSUREResponse.protocolError("Application is not found by given Application ID: " + applicationId);
        }

        return PICSUREResponse.success(entityById.get());
    }

    @ApiOperation(value = "GET a list of existing Applications, no role restrictions")
    @GetMapping
    public ResponseEntity<?> getApplicationAll() {
        return PICSUREResponse.success(applicationService.getAllApplications());
    }

    @ApiOperation(value = "POST a list of Applications, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
    @PostMapping(value = "/", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> addApplication(
            @ApiParam(required = true, value = "A list of AccessRule in JSON format")
            List<Application> applications) {
        applications = applicationService.addNewApplications(applications);
        return PICSUREResponse.success(applications);
    }

    @ApiOperation(value = "Update a list of Applications, will only update the fields listed, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
    @PutMapping(value = "/", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> updateApplication(
            @ApiParam(required = true, value = "A list of AccessRule with fields to be updated in JSON format")
            List<Application> applications) {
        applications = applicationService.updateApplications(applications);
        return PICSUREResponse.success(applications);
    }

    @ApiOperation(value = "Refresh a token of an application by application Id, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
    @GetMapping(value = "/refreshToken/{applicationId}")
    public ResponseEntity<?> refreshApplicationToken(
            @ApiParam(required = true, value = "A valid application Id")
            @PathVariable("applicationId") String applicationId) {
        String newApplicationToken = applicationService.refreshApplicationToken(applicationId);
        return PICSUREResponse.success(Map.of("token", newApplicationToken));
    }

    @ApiOperation(value = "DELETE an Application by Id only if the application is not associated by others, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
    @DeleteMapping(value = "/{applicationId}")
    public ResponseEntity<?> removeById(
            @ApiParam(required = true, value = "A valid accessRule Id")
            @PathVariable("applicationId") final String applicationId) {
        try {
            List<Application> applications = applicationService.deleteApplicationById(applicationId);
            return PICSUREResponse.success(applications);
        } catch (IllegalArgumentException e) {
            return PICSUREResponse.protocolError(e.getMessage());
        }
    }

}
