package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.entity.Role;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.enums.SecurityRoles;
import edu.harvard.hms.dbmi.avillach.auth.model.CustomUserDetails;
import edu.harvard.hms.dbmi.avillach.auth.repository.RoleRepository;
import edu.harvard.hms.dbmi.avillach.auth.utils.FenceMappingUtility;
import jakarta.annotation.PostConstruct;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class RoleService {

    private final static Logger logger = LoggerFactory.getLogger(RoleService.class.getName());

    private final FenceMappingUtility fenceMappingUtility;
    private final RoleRepository roleRepository;
    private final PrivilegeService privilegeService;

    @Autowired
    protected RoleService(FenceMappingUtility fenceMappingUtility, RoleRepository roleRepository, PrivilegeService privilegeService) {
        this.fenceMappingUtility = fenceMappingUtility;
        this.roleRepository = roleRepository;
        this.privilegeService = privilegeService;
    }

    @PostConstruct
    public void init() {
        if (!fenceMappingUtility.getFENCEMapping().isEmpty() && !fenceMappingUtility.getFenceMappingByAuthZ().isEmpty()) {
            logger.info("FenceMappingUtility is initialized properly.");
            logger.info("Starting to load roles from fence_mapping.json to database.");

            // Create a list of role names
            Set<String> roleNames = this.fenceMappingUtility.getFENCEMapping().entrySet().parallelStream().map(studyMetadata -> {
                String projectId = studyMetadata.getValue().getStudyIdentifier();
                String consentCode = studyMetadata.getValue().getConsentGroupCode();
                return StringUtils.isNotBlank(consentCode) ? "FENCE_" + projectId + "_" + consentCode : "FENCE_" + projectId;
            }).collect(Collectors.toSet());

            // Get the list of roles that don't exist in the database. With bulk select, we can get all roles in one query.
            Set<Role> rolesThatExist = roleRepository.findByNameIn(roleNames);
            Set<String> existingRoleNames = rolesThatExist.parallelStream().map(Role::getName).collect(Collectors.toSet());
            roleNames.removeAll(existingRoleNames);
            logger.info("Roles that don't exist in the database: {}", roleNames);

            // Create a list of roles that don't exist in the database
            List<Role> newRoles = roleNames.parallelStream().map(roleName -> createRole(roleName, "FENCE role " + roleName)).toList();
            logger.info("New roles created: {}", newRoles.size());
            persistAll(newRoles);
        } else {
            logger.info("""
                    FenceMappingUtility is not initialized properly and likely did not find the templatePath.
                    If you are running this in a environment where you don't need the FenceMappingUtility,
                    this can be ignored.
                    """);
        }
    }

    public Optional<Role> getRoleById(String roleId) {
        return roleRepository.findById(UUID.fromString(roleId));
    }

    public Optional<Role> getRoleById(UUID roleId) {
        return roleRepository.findById(roleId);
    }

    public List<Role> getAllRoles() {
        return roleRepository.findAll();
    }

    @Transactional
    public List<Role> addRoles(List<Role> roles) {
        checkPrivilegeAssociation(roles);
        return roleRepository.saveAll(roles);
    }

    /**
     * check if the privileges under role is in the database or not,
     * then retrieve it from database and attach it to role object
     *
     * @param roles list of roles
     */
    private void checkPrivilegeAssociation(List<Role> roles) throws RuntimeException {
        for (Role role : roles) {
            if (role.getPrivileges() != null) {
                Set<Privilege> privileges = new HashSet<>();
                for (Privilege p : role.getPrivileges()) {
                    Optional<Privilege> privilege = this.privilegeService.findById(p.getUuid());
                    if (privilege.isEmpty()) {
                        throw new RuntimeException("Privilege not found - uuid: " + p.getUuid().toString());
                    }
                    privileges.add(privilege.get());
                }
                role.setPrivileges(privileges);
            }
        }

    }

    @Transactional
    public List<Role> updateRoles(List<Role> roles) {
        checkPrivilegeAssociation(roles);
        return roleRepository.saveAll(roles);
    }

    @Transactional
    public Optional<List<Role>> removeRoleById(String roleId) {
        Optional<Role> optionalRole = roleRepository.findById(UUID.fromString(roleId));

        if (optionalRole.isEmpty()) {
            return Optional.empty();
        }

        SecurityContext context = SecurityContextHolder.getContext();
        CustomUserDetails current_user = (CustomUserDetails) context.getAuthentication().getPrincipal();
        Set<String> roleNames = current_user.getUser().getRoles().stream().map(Role::getName).collect(Collectors.toSet());

        if (!roleNames.contains(SecurityRoles.PIC_SURE_TOP_ADMIN.getRole())) {
            logger.info("User doesn't have PIC-SURE Top Admin role, can't remove any role");
            return Optional.empty();
        }

        roleRepository.deleteById(optionalRole.get().getUuid());
        return Optional.of(roleRepository.findAll());
    }

    public void addObjectToSet(Set<Role> roles, Role t) {
        // check if the role exists in the database
        Role role = roleRepository.findById(t.getUuid()).orElse(null);
        if (role == null) {
            throw new RuntimeException("Role not found - uuid: " + t.getUuid().toString());
        }

        roles.add(t);
    }

    public Role getRoleByName(String fenceOpenAccessRoleName) {
        return this.roleRepository.findByName(fenceOpenAccessRoleName);
    }

    public Role save(Role r) {
        return this.roleRepository.save(r);
    }

    public Set<Role> getRolesByIds(Set<UUID> roleUuids) {
        return this.roleRepository.findByUuidIn(roleUuids);
    }

    public void persistAll(List<Role> newRoles) {
        this.roleRepository.saveAll(newRoles);
        this.roleRepository.flush();
    }

    public Role findByName(String roleName) {
        return this.roleRepository.findByName(roleName);
    }

    public Role createRole(String roleName, String roleDescription) {
        if (roleName.isEmpty()) {
            logger.info("createRole() roleName is empty");
            return null;
        }

        logger.info("createRole() New role name: {}", roleName);
        Role r;
        // Create the Role in the repository, if it does not exist. Otherwise, add it.
        // This is a new Role
        r = new Role();
        r.setName(roleName);
        r.setDescription(roleDescription);
        // Since this is a new Role, we need to ensure that the
        // corresponding Privilege (with gates) and AccessRule is added.
        r.setPrivileges(this.privilegeService.addFENCEPrivileges(r));
        return r;
    }

    /**
     * Insert or Update the User object's list of Roles in the database.
     *
     * @param u               The User object the generated Role will be added to
     * @param roleName        Name of the Role
     * @param roleDescription Description of the Role
     * @return boolean Whether the Role was successfully added to the User or not
     */
    public boolean upsertFenceRole(User u, String roleName, String roleDescription) {
        boolean status = false;

        // Get the User's list of Roles. The first time, this will be an empty Set.
        // This method is called for every Role, and the User's list of Roles will
        // be updated for all subsequent calls.
        try {
            Role r;
            // Create the Role in the Servicesitory, if it does not exist. Otherwise, add it.
            Role existing_role = getRoleByName(roleName);
            if (existing_role != null) {
                // Role already exists
                logger.info("upsertRole() role already exists");
                r = existing_role;
            } else {
                // This is a new Role
                r = new Role();
                r.setName(roleName);
                r.setDescription(roleDescription);
                // Since this is a new Role, we need to ensure that the
                // corresponding Privilege (with gates) and AccessRule is added.
                r.setPrivileges(this.privilegeService.addFENCEPrivileges(r));
                save(r);
                logger.info("upsertRole() created new role");
            }
            if (u != null) {
                u.getRoles().add(r);
            }
            status = true;
        } catch (Exception ex) {
            logger.error("upsertRole() Could not inser/update role {} to Service", roleName, ex);
        }


        logger.debug("upsertRole() finished");
        return status;
    }

    public Set<Role> findByNameIn(Set<String> roleNames) {
        return this.roleRepository.findByNameIn(roleNames);
    }
}

