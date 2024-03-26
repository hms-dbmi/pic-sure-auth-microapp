package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.entity.Connection;
import edu.harvard.hms.dbmi.avillach.auth.entity.UserMetadataMapping;
import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.repository.ConnectionRepository;
import edu.harvard.hms.dbmi.avillach.auth.repository.UserMetadataMappingRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;

/**
 * <p>Provides business logic for UserMetadataMapping endpoint.</p>
 */
@Service
public class UserMetadataMappingService extends BaseEntityService<UserMetadataMapping> {

    private final UserMetadataMappingRepository userMetadataMappingRepo;

    private final ConnectionRepository connectionRepo;

    @Autowired
    public UserMetadataMappingService(UserMetadataMappingRepository userMetadataMappingRepo, ConnectionRepository connectionRepo) {
        super(UserMetadataMapping.class);
        this.userMetadataMappingRepo = userMetadataMappingRepo;
        this.connectionRepo = connectionRepo;
    }

    public List<UserMetadataMapping> getAllMappingsForConnection(Connection connection) {
        return userMetadataMappingRepo.findByConnection(connection);
    }

    @Transactional
    public ResponseEntity<?> addMappings(List<UserMetadataMapping> mappings) {
        String errorMessage = "The following connectionIds do not exist:\n";
        boolean error = false;
        for (UserMetadataMapping umm : mappings) {
            Connection c = connectionRepo.findConnectionById(umm.getConnection().getId());
            if (c == null) {
                error = true;
                errorMessage += umm.getConnection().getId() + "\n";
            } else {
                umm.setConnection(c);
            }
        }
        if (error) {
            return PICSUREResponse.success(errorMessage);
        }
        return addEntity(mappings, userMetadataMappingRepo);
    }

    public List<UserMetadataMapping> getAllMappings() {
        return userMetadataMappingRepo.list();
    }

    public ResponseEntity<?> getAllMappingsForConnection(String connection) {
        return PICSUREResponse.success(getAllMappingsForConnection(connectionRepo.getUniqueResultByColumn("id", connection)));
    }

    public ResponseEntity<?> updateEntity(List<UserMetadataMapping> mappings) {
        return this.updateEntity(mappings, userMetadataMappingRepo);
    }

    @Transactional
    public ResponseEntity<?> removeEntityById(String mappingId) {
        return this.removeEntityById(mappingId, userMetadataMappingRepo);
    }
}
