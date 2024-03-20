package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.entity.Connection;
import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.repository.ConnectionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ConnectionWebService extends BaseEntityService<Connection> {

    private final ConnectionRepository connectionRepo;

    @Autowired
    protected ConnectionWebService(Class<Connection> type, ConnectionRepository connectionRepo) {
        super(type);
        this.connectionRepo = connectionRepo;
    }

    public ResponseEntity<?> addEntity(List<Connection> connections){
        for (Connection c : connections){
            if (c.getSubPrefix() == null || c.getRequiredFields() == null || c.getLabel() == null || c.getId() == null){
                return PICSUREResponse.protocolError("Id, Label, Subprefix, and RequiredFields cannot be null");
            }
            Connection conn = connectionRepo.findConnectionById(c.getId());
            if (conn != null){
                return PICSUREResponse.protocolError("Id must be unique, a connection with id " + c.getId() + " already exists in the database");
            }
        }
        return addEntity(connections, connectionRepo); // TODO: This should be moved to an actual service class. We shouldn't need to pass a repo to the service class
    }

    public ResponseEntity<?> getEntityById(String connectionId) {
        return getEntityById(connectionId, connectionRepo);
    }

    public ResponseEntity<?> getEntityAll() {
        return getEntityAll(connectionRepo);
    }

    public ResponseEntity<?> updateEntity(List<Connection> connections) {
        return updateEntity(connections, connectionRepo);
    }

    public ResponseEntity<?> removeEntityById(String connectionId) {
        return removeEntityById(connectionId, connectionRepo);
    }
}
