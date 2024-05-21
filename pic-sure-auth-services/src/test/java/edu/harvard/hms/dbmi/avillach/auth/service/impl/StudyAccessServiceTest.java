package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication.FENCEAuthenticationService;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

public class StudyAccessServiceTest {

    @InjectMocks
    private StudyAccessService studyAccessService;

    @Mock
    private FENCEAuthenticationService fenceAuthenticationService;

    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);
    }


    @Test
    public void testAddStudyAccessWithBlankIdentifier() {
        String studyIdentifier = "";
        ResponseEntity<?> responseEntity = studyAccessService.addStudyAccess(studyIdentifier);
        assertEquals(ResponseEntity.internalServerError().body("Study identifier cannot be blank"), responseEntity);
    }

    @Test
    public void testAddStudyAccess() {
        String studyIdentifier = "testStudy";
        when(fenceAuthenticationService.getFENCEMapping()).thenReturn(Map.of(studyIdentifier, Map.of(StudyAccessService.STUDY_IDENTIFIER, studyIdentifier,StudyAccessService.CONSENT_GROUP_CODE, "")));
        when(fenceAuthenticationService.upsertRole(null, "MANUAL_testStudy", "MANUAL_ role MANUAL_testStudy")).thenReturn(true);

        ResponseEntity<?> responseEntity = studyAccessService.addStudyAccess(studyIdentifier);
        assertEquals(ResponseEntity.ok("Role 'MANUAL_testStudy' successfully created"), responseEntity);
    }

    @Test
    public void testAddStudyAccessWithConsent() {
        String studyIdentifier = "testStudy2.c2";
        when(fenceAuthenticationService.getFENCEMapping()).thenReturn(Map.of(studyIdentifier, Map.of(StudyAccessService.STUDY_IDENTIFIER, "testStudy2", StudyAccessService.CONSENT_GROUP_CODE, "c2")));
        when(fenceAuthenticationService.upsertRole(null, "MANUAL_testStudy2_c2", "MANUAL_ role MANUAL_testStudy2_c2")).thenReturn(true);
        ResponseEntity<?> responseEntity = studyAccessService.addStudyAccess(studyIdentifier);
        assertEquals(ResponseEntity.ok("Role 'MANUAL_testStudy2_c2' successfully created"), responseEntity);
    }
}