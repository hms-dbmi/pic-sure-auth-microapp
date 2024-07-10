package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.entity.Role;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.enums.SecurityRoles;
import edu.harvard.hms.dbmi.avillach.auth.model.CustomUserDetails;
import edu.harvard.hms.dbmi.avillach.auth.repository.PrivilegeRepository;
import edu.harvard.hms.dbmi.avillach.auth.repository.RoleRepository;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class RoleServiceTest {

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PrivilegeRepository privilegeRepo;

    @Mock
    private SecurityContext securityContext;

    @Mock
    private Authentication authentication;

    @InjectMocks
    private RoleService roleService;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);
    }

    @Test
    public void testGetRoleById_String() {
        UUID roleId = UUID.randomUUID();
        Role role = new Role();
        role.setUuid(roleId);

        when(roleRepository.findById(roleId)).thenReturn(Optional.of(role));

        Optional<Role> result = roleService.getRoleById(roleId.toString());

        assertTrue(result.isPresent());
        assertEquals(role, result.get());
        verify(roleRepository, times(1)).findById(roleId);
    }

    @Test
    public void testGetRoleById_UUID() {
        UUID roleId = UUID.randomUUID();
        Role role = new Role();
        role.setUuid(roleId);

        when(roleRepository.findById(roleId)).thenReturn(Optional.of(role));

        Optional<Role> result = roleService.getRoleById(roleId);

        assertTrue(result.isPresent());
        assertEquals(role, result.get());
        verify(roleRepository, times(1)).findById(roleId);
    }

    @Test
    public void testGetAllRoles() {
        List<Role> roles = Arrays.asList(new Role(), new Role());

        when(roleRepository.findAll()).thenReturn(roles);

        List<Role> result = roleService.getAllRoles();

        assertEquals(roles, result);
        verify(roleRepository, times(1)).findAll();
    }

    @Test
    public void testAddRoles() {
        List<Role> roles = Arrays.asList(new Role(), new Role());

        when(roleRepository.saveAll(roles)).thenReturn(roles);

        List<Role> result = roleService.addRoles(roles);

        assertEquals(roles, result);
        verify(roleRepository, times(1)).saveAll(roles);
    }

    @Test(expected = RuntimeException.class)
    public void testAddRoles_PrivilegeNotFound() {
        Role role = new Role();
        Privilege privilege = new Privilege();
        privilege.setUuid(UUID.randomUUID());
        role.setPrivileges(new HashSet<>(Collections.singletonList(privilege)));

        when(privilegeRepo.findById(privilege.getUuid())).thenReturn(Optional.empty());

        roleService.addRoles(Collections.singletonList(role));
    }

    @Test
    public void testUpdateRoles() {
        List<Role> roles = Arrays.asList(new Role(), new Role());

        when(roleRepository.saveAll(roles)).thenReturn(roles);

        List<Role> result = roleService.updateRoles(roles);

        assertEquals(roles, result);
        verify(roleRepository, times(1)).saveAll(roles);
    }

    @Test(expected = RuntimeException.class)
    public void testUpdateRoles_PrivilegeNotFound() {
        Role role = new Role();
        Privilege privilege = new Privilege();
        privilege.setUuid(UUID.randomUUID());
        role.setPrivileges(new HashSet<>(Collections.singletonList(privilege)));

        when(privilegeRepo.findById(privilege.getUuid())).thenReturn(Optional.empty());

        roleService.updateRoles(Collections.singletonList(role));
    }

    @Test
    public void testRemoveRoleById_Success() {
        User user = createTestUser();
        configureUserSecurityContext(user);

        Set<Role> roles = user.getRoles();
        Role role = roles.iterator().next();
        UUID roleId = role.getUuid();

        when(roleRepository.findById(roleId)).thenReturn(Optional.of(role));
        when(roleRepository.findAll()).thenReturn(Collections.singletonList(role));

        Optional<List<Role>> result = roleService.removeRoleById(roleId.toString());

        assertTrue(result.isPresent());
        assertEquals(1, result.get().size());
        verify(roleRepository, times(1)).deleteById(roleId);
        verify(roleRepository, times(1)).findAll();
    }

    @Test
    public void testRemoveRoleById_RoleNotFound() {
        UUID roleId = UUID.randomUUID();

        when(roleRepository.findById(roleId)).thenReturn(Optional.empty());

        Optional<List<Role>> result = roleService.removeRoleById(roleId.toString());

        assertFalse(result.isPresent());
        verify(roleRepository, never()).deleteById(any());
    }

    @Test
    public void testRemoveRoleById_InsufficientPrivileges() {
        UUID roleId = UUID.randomUUID();
        Role role = new Role();
        role.setUuid(roleId);

        User user = createTestUserWithoutPrivileges();
        configureUserSecurityContext(user);

        when(roleRepository.findById(roleId)).thenReturn(Optional.of(role));

        Optional<List<Role>> result = roleService.removeRoleById(roleId.toString());

        assertFalse(result.isPresent());
        verify(roleRepository, never()).deleteById(any());
    }

    @Test
    public void testAddObjectToSet_RoleExists() {
        Set<Role> roles = new HashSet<>();
        Role role = new Role();
        role.setUuid(UUID.randomUUID());

        when(roleRepository.findById(role.getUuid())).thenReturn(Optional.of(role));

        roleService.addObjectToSet(roles, role);

        assertTrue(roles.contains(role));
    }

    @Test(expected = RuntimeException.class)
    public void testAddObjectToSet_RoleNotFound() {
        Set<Role> roles = new HashSet<>();
        Role role = new Role();
        role.setUuid(UUID.randomUUID());

        when(roleRepository.findById(role.getUuid())).thenReturn(Optional.empty());

        roleService.addObjectToSet(roles, role);
    }

    private Role createTopAdminRole() {
        Role role = new Role();
        role.setName(SecurityRoles.PIC_SURE_TOP_ADMIN.getRole());
        role.setUuid(UUID.randomUUID());
        role.setPrivileges(Collections.singleton(createSuperAdminPrivilege()));
        return role;
    }

    private Privilege createSuperAdminPrivilege() {
        Privilege privilege = new Privilege();
        privilege.setName(AuthNaming.AuthRoleNaming.SUPER_ADMIN);
        privilege.setUuid(UUID.randomUUID());
        return privilege;
    }

    private void configureUserSecurityContext(User user) {
        CustomUserDetails customUserDetails = new CustomUserDetails(user);

        // configure security context
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        when(securityContext.getAuthentication()).thenReturn(authentication);
    }

    private User createTestUser() {
        User user = new User();
        user.setUuid(UUID.randomUUID());
        user.setRoles(new HashSet<>(Collections.singleton(createTopAdminRole())));
        user.setSubject("TEST_SUBJECT");
        user.setEmail("test@email.com");
        user.setAcceptedTOS(new Date());
        user.setActive(true);

        return user;
    }

    private User createTestUserWithoutPrivileges() {
        User user = new User();
        user.setUuid(UUID.randomUUID());
        user.setRoles(new HashSet<>());
        user.setSubject("TEST_SUBJECT");
        user.setEmail("test@email.com");
        user.setAcceptedTOS(new Date());
        user.setActive(true);
        return user;
    }

    private Role createTopAdminRoleWithoutPrivs() {
        Role role = new Role();
        role.setName(SecurityRoles.PIC_SURE_TOP_ADMIN.getRole());
        role.setUuid(UUID.randomUUID());
        role.setPrivileges(Collections.emptySet());
        return role;
    }

}
