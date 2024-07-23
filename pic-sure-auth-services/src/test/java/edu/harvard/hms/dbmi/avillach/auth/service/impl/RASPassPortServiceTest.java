package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.hms.dbmi.avillach.auth.enums.PassportValidationResponse;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasDbgapPermission;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Base64;
import java.util.Optional;
import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class RASPassPortServiceTest {

    @Mock
    private RestClientUtil restClientUtil;

    @InjectMocks
    private RASPassPortService rasPassPortService;
//    https://stsstg.nih.gov
    @Before
    public void setUp() throws Exception {
        String[] splitString = exampleRasPassport.split("\\.");
        String base64EncodedPayload = splitString[1];
        Base64.Decoder decoder = Base64.getDecoder();
        String payload = new String(decoder.decode(base64EncodedPayload));

        ObjectMapper mapper = new ObjectMapper();
        exampleRasPassportJson = mapper.readTree(payload);

        rasPassPortService.setRasURI("https://test.com/");
    }

    private static final String exampleRasPassport = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImRlZmF1bHRfc3NsX2tleSJ9.ew0KInN1YiI6IjJLRWthUC1SeDJGdkJCOExRVjRucjVmZXlySG4yNXEwV3hVd1kxVDIwMnMiLA0KImp0aSI6ImNiZDFjMzkyLTk0YjYtNDc2Yi1iYjA5LTk2MWY4MTM3MmE2NCIsDQoic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEiLA0KInR4biI6IlRsdVJ1UVcvZlZrPS5mYWJkOTdkMTdkNGM4OGFiIiwNCiJpc3MiOiAiaHR0cHM6Ly9zdHNzdGcubmloLmdvdiIsIAoiaWF0IjogMTYyMDIxMDM2MiwKImV4cCI6IDE2MjAyNTM1NjIsCiJnYTRnaF9wYXNzcG9ydF92MSIgOiBbImV3MEtJQ0FpZEhsd0lqb2dJa3BYVkNJc0RRb2dJQ0poYkdjaU9pQWlVbE15TlRZaUxBMEtJQ0FpYTJsa0lqb2dJbVJsWm1GMWJIUmZjM05zWDJ0bGVTSU5DbjAuZXcwS0lDQWlhWE56SWpvZ0ltaDBkSEJ6T2k4dmMzUnpjM1JuTG01cGFDNW5iM1lpTEEwS0lDQWljM1ZpSWpvZ0lqSkxSV3RoVUMxU2VESkdka0pDT0V4UlZqUnVjalZtWlhseVNHNHlOWEV3VjNoVmQxa3hWREl3TW5NaUxDQU5DaUFnSW1saGRDSTZJREUyTWpBeU1UQXpOaklzRFFvZ0lDSmxlSEFpT2lBeE5qSXdNalV6TlRZeUxBMEtJQ0FpYzJOdmNHVWlPaUFpYjNCbGJtbGtJR2RoTkdkb1gzQmhjM053YjNKMFgzWXhJaXdOQ2lBZ0ltcDBhU0k2SUNJNU56UTNPV0UzTXkwMFltSmxMVFJoWVdVdE9HWTFNUzAxTldVNU9UQTBZalJqT1RnaUxBMEtJQ0FpZEhodUlqb2dJbFJzZFZKMVVWY3ZabFpyUFM1bVlXSmtPVGRrTVRka05HTTRPR0ZpSWl3TkNpQWdJbWRoTkdkb1gzWnBjMkZmZGpFaU9pQjdJQTBLSUNBZ0lDQWlkSGx3WlNJNklDSm9kSFJ3Y3pvdkwzSmhjeTV1YVdndVoyOTJMM1pwYzJGekwzWXhMakVpTENBTkNpQWdJQ0FnSW1GemMyVnlkR1ZrSWpvZ01UWXlNREl4TURNMk1pd05DaUFnSUNBZ0luWmhiSFZsSWpvZ0ltaDBkSEJ6T2k4dmMzUnpjM1JuTG01cGFDNW5iM1l2Y0dGemMzQnZjblF2WkdKbllYQXZkakV1TVNJc0RRb2dJQ0FnSUNKemIzVnlZMlVpT2lBaWFIUjBjSE02THk5dVkySnBMbTVzYlM1dWFXZ3VaMjkyTDJkaGNDSXNEUW9nSUNBZ0lDSmllU0k2SUNKa1lXTWlmU3dOQ2lBZ0lDQWdJbkpoYzE5a1ltZGhjRjl3WlhKdGFYTnphVzl1Y3lJNklGc05DaUFnSUNBZ0lDQWdJQTBLZXcwS0ltTnZibk5sYm5SZmJtRnRaU0k2SWtkbGJtVnlZV3dnVW1WelpXRnlZMmdnVlhObElpd0pEUW9pY0doelgybGtJam9pY0doek1EQXdNREEySWl3TkNpSjJaWEp6YVc5dUlqb2lkakVpTEEwS0luQmhjblJwWTJsd1lXNTBYM05sZENJNkluQXhJaXdKQ1EwS0ltTnZibk5sYm5SZlozSnZkWEFpT2lKak1TSXNEUW9pY205c1pTSTZJbkJwSWl3TkNpSmxlSEJwY21GMGFXOXVJam94TmpReE1ERXpNakF3RFFwOUxBMEtldzBLSW1OdmJuTmxiblJmYm1GdFpTSTZJa1Y0WTJoaGJtZGxJRUZ5WldFaUxBa05DaUp3YUhOZmFXUWlPaUp3YUhNd01EQXpNREFpTEEwS0luWmxjbk5wYjI0aU9pSjJNU0lzRFFvaWNHRnlkR2xqYVhCaGJuUmZjMlYwSWpvaWNERWlMQWtKRFFvaVkyOXVjMlZ1ZEY5bmNtOTFjQ0k2SW1NNU9Ua2lMQTBLSW5KdmJHVWlPaUp3YVNJc0RRb2laWGh3YVhKaGRHbHZiaUk2TVRZME1UQXhNekl3TUFrTkNuME5DaUFnSUNBZ1hTQU5DbjAuTnpSOEtzZTJOOUtFOXhvLUo4dXdUaWxzUG9pYXhNWGlGR0prY0JOYTMtOGt1ZEh3MFd6U0xDM3Z3Qk4yZ3Z0RUtMZ2ZBeVpVUDZrc0ktRzlOV0NIU3Z2RG4tbFNhbjVtV1dfWEhrRVdGWGd3RXotWlNNalBvV0Vndlk1bHhSWEhxR1lhWmQ5U2puTjdsTFpUbHNQLU9pbFUxcUNyQ205YzVfcTh1YWJyZ3o0OW5PWFRGZEpKblpPT1ZzUmtkU0NjVnlHczRlbUxNSjdDdVd2ckU2RkR2Ri1QTUpGNlhHYnN3R1pjVFRPM3h0MjR6Tk1wbm5RUEVzNXQ3Tk1LZjhucEJ3czNvd0FKcklTRkExYTNmUWtJZU83dFRUUGVSX1FRVUlxYzFJRW5JdlotMGdsNE5ETEZRSjJTTS1KdUtvSWdnQWt3NVNGWDNhSk9WNC12b2JZbXhBIl0NCn0.sJwAZeR8cYyF-BCluC9fmiQAi14L7hC3DB4MoFQNNdoakUBujPZ-NlpfP2rBgJQ3CGcxsF95Vdczm6Yk4TKa68eXkKjkswjsSSQg0qErgFhN2jis9KMxnMfmfPNUfb0lioHtD-_oghRkd9239oUwLR06KB5Ux3mD4Pc0ZPbJxJcPmyP9DZ8WEHmAFIJpcoayHwJDr1jt-GbqUtaTCs1VQ9Habh8Z8fvwrlvQNj744m5eq6141bD0G15KgvbyYf9L4_PYNgMjTyUx9EGyetrxQ4XmOpDF_ZbFEhZliy80qfO2HGQzSId-dKXCvPI_SUWcCVeJqPwmXTirTt9qJ63ypw";
    private JsonNode exampleRasPassportJson;

    @Test
    public void testGa4ghPassPortStudies_IsNull() {
        Set<RasDbgapPermission> permissions = rasPassPortService.ga4gpPassportToRasDbgapPermissions(null);
        assertNull(permissions);
    }

    @Test
    public void testGa4gpPassportStudies_IsNotNull() {
        Set<RasDbgapPermission> permissions = rasPassPortService.ga4gpPassportToRasDbgapPermissions(exampleRasPassportJson);
        assertNotNull(permissions);
    }

    @Test
    public void testGa4gpPassportStudies_HasCorrectStudies() {
        Set<RasDbgapPermission> permissions = rasPassPortService.ga4gpPassportToRasDbgapPermissions(exampleRasPassportJson);

        assertEquals(2, permissions.size());
        assertTrue(permissions.stream().anyMatch(p -> p.getPhsId().equals("phs000300")));
        assertTrue(permissions.stream().anyMatch(p -> p.getPhsId().equals("phs000006")));
    }

    @Test
    public void testValidatePassport_Valid() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("{\"status\": \"Valid\"}", HttpStatus.OK));
        Optional<JsonNode> response = rasPassPortService.validatePassport("validPassport");
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.VALID.getValue(), response.get().get("status").asText());
    }

    @Test
    public void testValidatePassport_Invalid() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("{\"status\": \"Invalid\"}", HttpStatus.OK));
        Optional<JsonNode> response = rasPassPortService.validatePassport("invalidPassport");
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.INVALID.getValue(), response.get().get("status").asText());
    }

    @Test
    public void testValidatePassport_Missing() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("{\"status\": \"Missing\"}", HttpStatus.OK));
        Optional<JsonNode> response = rasPassPortService.validatePassport("missingPassport");
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.MISSING.getValue(), response.get().get("status").asText());
    }

    @Test
    public void testValidatePassport_InvalidPassport() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("{\"status\": \"Invalid Passport\"}", HttpStatus.OK));
        Optional<JsonNode> response = rasPassPortService.validatePassport("invalidFormatPassport");
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.INVALID_PASSPORT.getValue(), response.get().get("status").asText());
    }

    @Test
    public void testValidatePassport_VisaExpired() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("{\"status\": \"Visa Expired\"}", HttpStatus.OK));
        Optional<JsonNode> response = rasPassPortService.validatePassport("expiredVisaPassport");
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.VISA_EXPIRED.getValue(), response.get().get("status").asText());
    }

    @Test
    public void testValidatePassport_TxnError() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("{\"status\": \"Txn Error\"}", HttpStatus.OK));
        Optional<JsonNode> response = rasPassPortService.validatePassport("txnErrorPassport");
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.TXN_ERROR.getValue(), response.get().get("status").asText());
    }

    @Test
    public void testValidatePassport_ExpirationError() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("{\"status\": \"Expiration Error\"}", HttpStatus.OK));
        Optional<JsonNode> response = rasPassPortService.validatePassport("expirationErrorPassport");
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.EXPIRATION_ERROR.getValue(), response.get().get("status").asText());
    }

    @Test
    public void testValidatePassport_ValidationError() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("{\"status\": \"Validation Error\"}", HttpStatus.OK));
        Optional<JsonNode> response = rasPassPortService.validatePassport("validationErrorPassport");
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.VALIDATION_ERROR.getValue(), response.get().get("status").asText());
    }

    @Test
    public void testValidatePassport_ExpiredPolling() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("{\"status\": \"Expired Polling\"}", HttpStatus.OK));
        Optional<JsonNode> response = rasPassPortService.validatePassport("expiredPollingPassport");
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.EXPIRED_POLLING.getValue(), response.get().get("status").asText());
    }

    @Test
    public void testValidatePassport_PermissionUpdate() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("{\"status\": \"Permission Update\"}", HttpStatus.OK));
        Optional<JsonNode> response = rasPassPortService.validatePassport("permissionUpdatePassport");
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.PERMISSION_UPDATE.getValue(), response.get().get("status").asText());
    }

}