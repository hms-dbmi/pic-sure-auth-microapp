package edu.harvard.hms.dbmi.avillach.auth.service;

import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.repository.PrivilegeRepository;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.BaseEntityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;
import java.util.UUID;

import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.ADMIN;

@Service
public class PrivilegeService extends BaseEntityService<Privilege> {

    private final static Logger logger = LoggerFactory.getLogger(PrivilegeService.class.getName());

    private final PrivilegeRepository privilegeRepository;

    @Autowired
    protected PrivilegeService(Class<Privilege> type, PrivilegeRepository privilegeRepository) {
        super(type);
        this.privilegeRepository = privilegeRepository;
    }

    @Transactional
    public ResponseEntity<?> deletePrivilegeByPrivilegeId(String privilegeId) {
        Privilege privilege = this.privilegeRepository.getById(UUID.fromString(privilegeId));

        // Get security context with spring security context
        SecurityContext securityContext = SecurityContextHolder.getContext();
        // Get the principal name from the security context
        String principalName = securityContext.getAuthentication().getName();

        if (ADMIN.equals(privilege.getName()))  {
            logger.info("User: " + principalName
                    + ", is trying to remove the system admin privilege: " + ADMIN);
            return PICSUREResponse.protocolError("System Admin privilege cannot be removed - uuid: " + privilege.getUuid().toString()
                    + ", name: " + privilege.getName());
        }

        return removeEntityById(privilegeId, this.privilegeRepository);
    }

    public ResponseEntity<?> updateEntity(List<Privilege> privileges) {
        return updateEntity(privileges, this.privilegeRepository);
    }

    public ResponseEntity<?> addEntity(List<Privilege> privileges) {
        return addEntity(privileges, this.privilegeRepository);
    }

    public ResponseEntity<?> getEntityAll() {
        return getEntityAll(this.privilegeRepository);
    }

    public ResponseEntity<?> getEntityById(String privilegeId) {
        return getEntityById(privilegeId, this.privilegeRepository);
    }
}
