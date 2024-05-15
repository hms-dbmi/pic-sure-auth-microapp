package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.repository.ApplicationRepository;
import edu.harvard.hms.dbmi.avillach.auth.repository.PrivilegeRepository;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

public class ApplicationServiceTest {

    @Mock
    private ApplicationRepository applicationRepo;

    @Mock
    private PrivilegeRepository privilegeRepo;

    @Mock
    private JWTUtil jwtUtil;

    @InjectMocks
    private ApplicationService applicationService;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testGetApplicationByID_found() {
        UUID id = UUID.randomUUID();
        Application app = new Application();
        app.setUuid(id);
        when(applicationRepo.findById(id)).thenReturn(Optional.of(app));

        Optional<Application> result = applicationService.getApplicationByID(id.toString());
        assertTrue(result.isPresent());
        assertSame(app, result.get());
    }

    @Test
    public void testGetApplicationByID_notFound() {
        UUID id = UUID.randomUUID();
        when(applicationRepo.findById(id)).thenReturn(Optional.empty());

        Optional<Application> result = applicationService.getApplicationByID(id.toString());
        assertFalse(result.isPresent());
    }

    @Test
    public void testGetApplicationByIdWithPrivileges_foundWithPrivileges() {
        UUID id = UUID.randomUUID();
        Application app = new Application();
        app.setPrivileges(new HashSet<>());
        when(applicationRepo.findById(id)).thenReturn(Optional.of(app));
        when(privilegeRepo.findById(any())).thenReturn(Optional.of(new Privilege()));

        Optional<Application> result = applicationService.getApplicationByIdWithPrivileges(id.toString());
        assertTrue(result.isPresent());
        assertNotNull(result.get().getPrivileges());
    }

    @Test
    public void testGetApplicationByIdWithPrivileges_notFound() {
        UUID id = UUID.randomUUID();
        when(applicationRepo.findById(id)).thenReturn(Optional.empty());

        Optional<Application> result = applicationService.getApplicationByIdWithPrivileges(id.toString());
        assertFalse(result.isPresent());
    }

    @Test
    public void testGetAllApplications_empty() {
        when(applicationRepo.findAll()).thenReturn(Collections.emptyList());

        List<Application> result = applicationService.getAllApplications();
        assertTrue(result.isEmpty());
    }

    @Test
    public void testGetAllApplications_nonEmpty() {
        when(applicationRepo.findAll()).thenReturn(Arrays.asList(new Application(), new Application()));

        List<Application> result = applicationService.getAllApplications();
        assertEquals(2, result.size());
    }

    @Test
    public void testAddNewApplications_successfulWithToken() {
        Application application = new Application();
        application.setUuid(UUID.randomUUID());
        List<Application> applications = Collections.singletonList(application);
        when(applicationRepo.saveAll(applications)).thenReturn(applications);
        when(jwtUtil.createJwtToken(any(), any(), any(), anyString(), anyLong())).thenReturn("token");

        List<Application> savedApps = applicationService.addNewApplications(applications);
        assertNotNull(savedApps);
        assertFalse(savedApps.isEmpty());
        assertEquals("token", savedApps.getFirst().getToken());
    }

    @Test
    public void testDeleteApplicationById_existing() {
        UUID id = UUID.randomUUID();
        Application application = new Application();
        when(applicationRepo.findById(id)).thenReturn(Optional.of(application));

        List<Application> remainingApps = applicationService.deleteApplicationById(id.toString());
        verify(applicationRepo, times(1)).delete(application);
        assertNotNull(remainingApps);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDeleteApplicationById_notFound() {
        UUID id = UUID.randomUUID();
        when(applicationRepo.findById(id)).thenReturn(Optional.empty());

        applicationService.deleteApplicationById(id.toString());
    }

    @Test
    public void testUpdateApplications() {
        Application application = new Application();
        application.setUuid(UUID.randomUUID());
        List<Application> applications = Collections.singletonList(application);
        when(applicationRepo.saveAll(anyList())).thenReturn(applications);

        List<Application> updatedApps = applicationService.updateApplications(applications);
        assertNotNull(updatedApps);
        assertEquals(applications.size(), updatedApps.size());
    }

    @Test
    public void testRefreshApplicationToken_successful() {
        UUID id = UUID.randomUUID();
        Application application = new Application();
        application.setUuid(id);
        application.setName("App");
        when(applicationRepo.findById(id)).thenReturn(Optional.of(application));
        when(jwtUtil.createJwtToken(any(), any(), any(), anyString(), anyLong())).thenReturn("newToken");

        String token = applicationService.refreshApplicationToken(id.toString());
        assertEquals("newToken", token);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRefreshApplicationToken_notFound() {
        UUID id = UUID.randomUUID();
        when(applicationRepo.findById(id)).thenReturn(Optional.empty());

        applicationService.refreshApplicationToken(id.toString());
    }

    @Test(expected = NullPointerException.class)
    public void testRefreshApplicationToken_failedToGenerateToken() {
        UUID id = UUID.randomUUID();
        Application application = new Application();
        application.setUuid(id);
        when(applicationRepo.findById(id)).thenReturn(Optional.of(application));
        when(jwtUtil.createJwtToken(any(), any(), any(), anyString(), anyLong())).thenReturn(null);

        applicationService.refreshApplicationToken(id.toString());
    }
}
