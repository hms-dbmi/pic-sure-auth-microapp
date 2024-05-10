package edu.harvard.hms.dbmi.avillach;

import edu.harvard.hms.dbmi.avillach.auth.data.repository.RoleRepository;
import edu.harvard.hms.dbmi.avillach.auth.model.BioDataCatalyst;
import edu.harvard.hms.dbmi.avillach.auth.rest.StudyAccessService;
import edu.harvard.hms.dbmi.avillach.auth.service.auth.FENCEAuthenticationService;
import edu.harvard.hms.dbmi.avillach.auth.utils.FenceMappingUtility;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

public class StudyAccessServiceTest {

    @InjectMocks
    private StudyAccessService studyAccessService;

    @Mock
    private FENCEAuthenticationService fenceAuthenticationService;

    @Mock
    private FenceMappingUtility fenceMappingUtility;

    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);
    }


    @Test
    public void testAddStudyAccessWithBlankIdentifier() {
        String studyIdentifier = "";
        Response response = studyAccessService.addStudyAccess(studyIdentifier);
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        assertEquals("Study identifier cannot be blank", response.getEntity());
    }

    @Test
    public void testAddStudyAccess() {
        String studyIdentifier = "testStudy";
        BioDataCatalyst bioDataCatalyst = new BioDataCatalyst();
        bioDataCatalyst.setStudy_identifier("testStudy");
        bioDataCatalyst.setConsent_group_code("");
        when(fenceMappingUtility.getFENCEMapping()).thenReturn(Map.of(studyIdentifier, bioDataCatalyst));
        when(fenceAuthenticationService.upsertRole(null, "MANUAL_testStudy", "MANUAL_ role MANUAL_testStudy")).thenReturn(true);

        Response response = studyAccessService.addStudyAccess(studyIdentifier);
        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        assertEquals("Role 'MANUAL_testStudy' successfully created", response.getEntity());
    }

    @Test
    public void testAddStudyAccessWithConsent() {
        String studyIdentifier = "testStudy2.c2";
        BioDataCatalyst bioDataCatalyst = new BioDataCatalyst();
        bioDataCatalyst.setStudy_identifier("testStudy2");
        bioDataCatalyst.setConsent_group_code("c2");

        when(fenceMappingUtility.getFENCEMapping()).thenReturn(Map.of(studyIdentifier, bioDataCatalyst));
        when(fenceAuthenticationService.upsertRole(null, "MANUAL_testStudy2_c2", "MANUAL_ role MANUAL_testStudy2_c2")).thenReturn(true);
        Response response = studyAccessService.addStudyAccess(studyIdentifier);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        assertEquals("Role 'MANUAL_testStudy2_c2' successfully created", response.getEntity());
    }
}