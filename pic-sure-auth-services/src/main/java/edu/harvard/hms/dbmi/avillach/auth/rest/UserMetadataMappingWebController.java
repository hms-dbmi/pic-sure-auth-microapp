package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.hms.dbmi.avillach.auth.entity.UserMetadataMapping;
import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.UserMetadataMappingService;
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
 * <p>Endpoint for service handling business logic for user metadata mapping.</p>
 * <p><Note: Only users with the super admin role can access this endpoint.</p>
 */
@Api
@Controller
@RequestMapping("/mapping")
public class UserMetadataMappingWebController {

	private final UserMetadataMappingService mappingService;

	@Autowired
    public UserMetadataMappingWebController(UserMetadataMappingService mappingService) {
        this.mappingService = mappingService;
    }

    @ApiOperation(value = "GET information of one UserMetadataMapping with the UUID, requires ADMIN or SUPER_ADMIN role")
    @RolesAllowed({ADMIN, SUPER_ADMIN})
	@GetMapping(path = "{connectionId}", produces = "application/json")
	public ResponseEntity<?> getMappingsForConnection(@PathVariable("connectionId") String connection) {
		return this.mappingService.getAllMappingsForConnection(connection);
	}

    @ApiOperation(value = "GET a list of existing UserMetadataMappings, requires ADMIN or SUPER_ADMIN role")
    @RolesAllowed({ADMIN, SUPER_ADMIN})
	@GetMapping(path = "/", produces = "application/json")
	public ResponseEntity<?> getAllMappings() {
		List<UserMetadataMapping> allMappings = mappingService.getAllMappings();
		return PICSUREResponse.success(allMappings);
	}

    @ApiOperation(value = "POST a list of UserMetadataMappings, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
	@PostMapping(path = "/", consumes = "application/json", produces = "application/json")
	public ResponseEntity<?> addMapping(
            @ApiParam(required = true, value = "A list of UserMetadataMapping in JSON format")
            List<UserMetadataMapping> mappings) {
		return mappingService.addMappings(mappings);
	}

    @ApiOperation(value = "Update a list of UserMetadataMappings, will only update the fields listed, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
	@PutMapping(path = "/", consumes = "application/json", produces = "application/json")
	public ResponseEntity<?> updateMapping(
            @ApiParam(required = true, value = "A list of UserMetadataMapping with fields to be updated in JSON format")
            List<UserMetadataMapping> mappings) {
		return this.mappingService.updateEntity(mappings);
	}

    @ApiOperation(value = "DELETE an UserMetadataMapping by Id only if the UserMetadataMapping is not associated by others, requires SUPER_ADMIN role")
    @RolesAllowed({SUPER_ADMIN})
	@DeleteMapping(path = "/{mappingId}", produces = "application/json")
	public ResponseEntity<?> removeById(
            @ApiParam(required = true, value = "A valid UserMetadataMapping Id")
            @PathVariable("mappingId") final String mappingId) {
		return this.mappingService.removeEntityById(mappingId);
	}
}
