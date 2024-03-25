package edu.harvard.hms.dbmi.avillach.auth.service;

import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.entity.Role;
import edu.harvard.hms.dbmi.avillach.auth.enums.SecurityRoles;
import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.repository.PrivilegeRepository;
import edu.harvard.hms.dbmi.avillach.auth.repository.RoleRepository;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.BaseEntityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@Service
public class RoleService extends BaseEntityService<Role> {

    private final static Logger logger = Logger.getLogger(RoleService.class.getName());
    private final RoleRepository roleRepository;

    private final PrivilegeRepository privilegeRepo;

    @Autowired
    protected RoleService(Class<Role> type, RoleRepository roleRepository, PrivilegeRepository privilegeRepo) {
        super(type);
        this.roleRepository = roleRepository;
        this.privilegeRepo = privilegeRepo;
    }

    public ResponseEntity<?> getEntityById(String roleId) {
        return getEntityById(roleId, roleRepository);
    }


    public ResponseEntity<?> getEntityAll() {
        return getEntityAll(roleRepository);
    }

    @Transactional
    public ResponseEntity<?> addEntity(List<Role> roles) {
        checkPrivilegeAssociation(roles);
        return addEntity(roles, roleRepository);
    }

    /**
     * check if the privileges under role is in the database or not,
     * then retrieve it from database and attach it to role object
     *
     * @param roles list of roles
     */
    private void checkPrivilegeAssociation(List<Role> roles) throws RuntimeException {
        for (Role role: roles){
            if (role.getPrivileges() != null) {
                Set<Privilege> privileges = new HashSet<>(); // TODO: Determine how we can fix this issue. The javax code does not work with java 21 in this case.
                role.getPrivileges().stream().forEach(p -> privilegeRepo.addObjectToSet(privileges, privilegeRepo, p));
                role.setPrivileges(privileges);
            }
        }

    }

    @Transactional
    public ResponseEntity<?> updateEntity(List<Role> roles) {
        checkPrivilegeAssociation(roles);
        return updateEntity(roles, roleRepository);
    }

    @Transactional
    public ResponseEntity<?> removeEntityById(String roleId) {
        Role role = roleRepository.getById(UUID.fromString(roleId));

        // Get principal roles from security context
        SecurityContext context = SecurityContextHolder.getContext();
        Set<String> roles = context.getAuthentication().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toSet());


        if (SecurityRoles.contains(roles, SecurityRoles.PIC_SURE_TOP_ADMIN.getRole())){
            logger.info("User has PIC-SURE Top Admin role, can remove any role");
            return PICSUREResponse.protocolError("Default System Role cannot be removed - uuid: " + role.getUuid().toString()
                    + ", name: " + role.getName());
        }
        return removeEntityById(roleId, roleRepository);
    }
}

