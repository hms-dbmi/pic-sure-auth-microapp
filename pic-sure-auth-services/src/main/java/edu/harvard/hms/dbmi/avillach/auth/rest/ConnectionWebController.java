package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.hms.dbmi.avillach.auth.entity.Connection;
import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.ConnectionWebService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.transaction.Transactional;
import java.util.List;

import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.ADMIN;
import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.SUPER_ADMIN;

/**
 * <p>Endpoint for service handling business logic for connections to PSAMA. <br>
 * Note: Only users with the super admin role can access this endpoint.</p>
 */
@Api
@Controller
@RequestMapping("/connection")
public class ConnectionWebController { // TODO: This isn't a service class, it's a controller. We should refactor this so it doesn't extend BaseEntityService


    private final ConnectionWebService connectionWebService;

    @Autowired
    public ConnectionWebController(ConnectionWebService connectionWebSerivce) {
        this.connectionWebService = connectionWebSerivce;
    }

    @ApiOperation(value = "GET information of one Connection with the UUID, requires ADMIN or SUPER_ADMIN role")
    @GetMapping(path = "/{connectionId}", produces = "application/json")
    @Secured({SUPER_ADMIN, ADMIN})
    public ResponseEntity<?> getConnectionById(
            @ApiParam(required = true, value = "The UUID of the Connection to fetch information about")
            @PathVariable("connectionId") String connectionId) {
        try {
            Connection connectionById = connectionWebService.getConnectionById(connectionId);
            return ResponseEntity.ok(connectionById);
        } catch (IllegalArgumentException e) {
            return PICSUREResponse.protocolError(e.getMessage());
        }
    }

    @ApiOperation(value = "GET a list of existing Connection, requires SUPER_ADMIN or ADMIN role")
    @GetMapping(path = "/", produces = "application/json")
    @Secured({SUPER_ADMIN, ADMIN})
    public ResponseEntity<?> getAllConnections() {
        List<Connection> allConnections = connectionWebService.getAllConnections();
        return ResponseEntity.ok(allConnections);
    }

    @ApiOperation(value = "POST a list of Connections, requires SUPER_ADMIN role")
    @Transactional
    @Secured({SUPER_ADMIN})
    @PostMapping(produces = "application/json", consumes = "application/json")
    public ResponseEntity<?> addConnection(
            @ApiParam(required = true, value = "A list of Connections in JSON format")
            List<Connection> connections) {
        try {
            connections = connectionWebService.addConnection(connections);
        } catch (IllegalArgumentException e) {
            return PICSUREResponse.protocolError(e.getMessage());
        }

        return PICSUREResponse.success("All connections are added.", connections);
    }

    @ApiOperation(value = "Update a list of Connections, will only update the fields listed, requires SUPER_ADMIN role")
    @Secured({SUPER_ADMIN})
    @PutMapping(produces = "application/json", consumes = "application/json")
    public ResponseEntity<?> updateConnection(
            @ApiParam(required = true, value = "A list of Connection with fields to be updated in JSON format")
            List<Connection> connections) {
        List<Connection> responseEntity = connectionWebService.updateConnections(connections);
        return ResponseEntity.ok(responseEntity);
    }

    @ApiOperation(value = "DELETE an Connection by Id only if the Connection is not associated by others, requires SUPER_ADMIN role")
    @Transactional
    @Secured({SUPER_ADMIN})
    @DeleteMapping(path = "/{connectionId}", produces = "application/json")
    public ResponseEntity<?> removeById(
            @ApiParam(required = true, value = "A valid connection Id")
            @PathVariable("connectionId") final String connectionId) {
        List<Connection> connections = connectionWebService.removeConnectionById(connectionId);
        return ResponseEntity.ok(connections);
    }


}
