package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.repository.ApplicationRepository;
import edu.harvard.hms.dbmi.avillach.auth.repository.ConnectionRepository;
import edu.harvard.hms.dbmi.avillach.auth.repository.UserRepository;
import edu.harvard.hms.dbmi.avillach.auth.service.RoleService;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Optional;
import java.util.UUID;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class UserServiceTest {


    @Mock
    private BasicMailService basicMailService;
    @Mock
    private TOSService tosService;
    @Mock
    private UserRepository userRepository;
    @Mock
    private ConnectionRepository connectionRepository;
    @Mock
    private ApplicationRepository applicationRepository;
    @Mock
    private RoleService roleService;
    @Mock
    private JWTUtil jwtUtil;

    private static final long defaultTokenExpirationTime = 1000L * 60 * 60; // 1 hour
    private String applicationUUID;
    private final long longTermTokenExpirationTime = 2592000000L;

    private UserService userService;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        applicationUUID = UUID.randomUUID().toString();
        userService = new UserService(
                basicMailService,
                tosService,
                userRepository,
                connectionRepository,
                applicationRepository,
                roleService,
                defaultTokenExpirationTime,
                applicationUUID,
                longTermTokenExpirationTime,
                jwtUtil);
    }

    @Test
    public void testGetUserById_found() {
        UUID testId = UUID.randomUUID();
        User mockUser = new User();
        mockUser.setUuid(testId);

        when(userRepository.findById(testId)).thenReturn(Optional.of(mockUser));

        User result = userService.getUserById(testId.toString());
        assertNotNull(result);
        assertEquals(testId, result.getUuid());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetUserById_notFound() {
        UUID testId = UUID.randomUUID();
        when(userRepository.findById(testId)).thenReturn(Optional.empty());

        userService.getUserById(testId.toString());
    }

}