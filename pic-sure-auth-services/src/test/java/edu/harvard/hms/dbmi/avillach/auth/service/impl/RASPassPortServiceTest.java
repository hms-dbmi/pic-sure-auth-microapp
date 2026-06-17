package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.dbmi.avillach.logging.LoggingClient;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.enums.PassportValidationResponse;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.Ga4ghPassportV1;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.Passport;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasDbgapPermission;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@SpringBootTest
@ContextConfiguration(classes = {RASPassPortService.class})
public class RASPassPortServiceTest {

    @MockBean
    private RestClientUtil restClientUtil;
    @MockBean
    private CacheEvictionService cacheEvictionService;
    @MockBean
    private UserService userService;
    @MockBean
    private LoggingClient loggingClient;

    private RASPassPortService rasPassPortService;

    private String visa;

    @BeforeEach
    public void setUp() throws Exception {
        this.rasPassPortService = new RASPassPortService(restClientUtil, null, "https://test.com/", cacheEvictionService, null);

        // Parse the passport and get the visa so we can mock the validateVisa method
        Optional<Passport> passport = JWTUtil.parsePassportJWTV11(exampleRasPassport);
        this.visa = passport.get().getGa4ghPassportV1().get(0);

    }

    private static final String exampleRasPassport = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImRlZmF1bHRfc3NsX2tleSJ9.ew0KInN1YiI6IjJLRWthUC1SeDJGdkJCOExRVjRucjVmZXlySG4yNXEwV3hVd1kxVDIwMnMiLA0KImp0aSI6ImNiZDFjMzkyLTk0YjYtNDc2Yi1iYjA5LTk2MWY4MTM3MmE2NCIsDQoic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEiLA0KInR4biI6IlRsdVJ1UVcvZlZrPS5mYWJkOTdkMTdkNGM4OGFiIiwNCiJpc3MiOiAiaHR0cHM6Ly9zdHNzdGcubmloLmdvdiIsIAoiaWF0IjogMTYyMDIxMDM2MiwKImV4cCI6IDE2MjAyNTM1NjIsCiJnYTRnaF9wYXNzcG9ydF92MSIgOiBbImV3MEtJQ0FpZEhsd0lqb2dJa3BYVkNJc0RRb2dJQ0poYkdjaU9pQWlVbE15TlRZaUxBMEtJQ0FpYTJsa0lqb2dJbVJsWm1GMWJIUmZjM05zWDJ0bGVTSU5DbjAuZXcwS0lDQWlhWE56SWpvZ0ltaDBkSEJ6T2k4dmMzUnpjM1JuTG01cGFDNW5iM1lpTEEwS0lDQWljM1ZpSWpvZ0lqSkxSV3RoVUMxU2VESkdka0pDT0V4UlZqUnVjalZtWlhseVNHNHlOWEV3VjNoVmQxa3hWREl3TW5NaUxDQU5DaUFnSW1saGRDSTZJREUyTWpBeU1UQXpOaklzRFFvZ0lDSmxlSEFpT2lBeE5qSXdNalV6TlRZeUxBMEtJQ0FpYzJOdmNHVWlPaUFpYjNCbGJtbGtJR2RoTkdkb1gzQmhjM053YjNKMFgzWXhJaXdOQ2lBZ0ltcDBhU0k2SUNJNU56UTNPV0UzTXkwMFltSmxMVFJoWVdVdE9HWTFNUzAxTldVNU9UQTBZalJqT1RnaUxBMEtJQ0FpZEhodUlqb2dJbFJzZFZKMVVWY3ZabFpyUFM1bVlXSmtPVGRrTVRka05HTTRPR0ZpSWl3TkNpQWdJbWRoTkdkb1gzWnBjMkZmZGpFaU9pQjdJQTBLSUNBZ0lDQWlkSGx3WlNJNklDSm9kSFJ3Y3pvdkwzSmhjeTV1YVdndVoyOTJMM1pwYzJGekwzWXhMakVpTENBTkNpQWdJQ0FnSW1GemMyVnlkR1ZrSWpvZ01UWXlNREl4TURNMk1pd05DaUFnSUNBZ0luWmhiSFZsSWpvZ0ltaDBkSEJ6T2k4dmMzUnpjM1JuTG01cGFDNW5iM1l2Y0dGemMzQnZjblF2WkdKbllYQXZkakV1TVNJc0RRb2dJQ0FnSUNKemIzVnlZMlVpT2lBaWFIUjBjSE02THk5dVkySnBMbTVzYlM1dWFXZ3VaMjkyTDJkaGNDSXNEUW9nSUNBZ0lDSmllU0k2SUNKa1lXTWlmU3dOQ2lBZ0lDQWdJbkpoYzE5a1ltZGhjRjl3WlhKdGFYTnphVzl1Y3lJNklGc05DaUFnSUNBZ0lDQWdJQTBLZXcwS0ltTnZibk5sYm5SZmJtRnRaU0k2SWtkbGJtVnlZV3dnVW1WelpXRnlZMmdnVlhObElpd0pEUW9pY0doelgybGtJam9pY0doek1EQXdNREEySWl3TkNpSjJaWEp6YVc5dUlqb2lkakVpTEEwS0luQmhjblJwWTJsd1lXNTBYM05sZENJNkluQXhJaXdKQ1EwS0ltTnZibk5sYm5SZlozSnZkWEFpT2lKak1TSXNEUW9pY205c1pTSTZJbkJwSWl3TkNpSmxlSEJwY21GMGFXOXVJam94TmpReE1ERXpNakF3RFFwOUxBMEtldzBLSW1OdmJuTmxiblJmYm1GdFpTSTZJa1Y0WTJoaGJtZGxJRUZ5WldFaUxBa05DaUp3YUhOZmFXUWlPaUp3YUhNd01EQXpNREFpTEEwS0luWmxjbk5wYjI0aU9pSjJNU0lzRFFvaWNHRnlkR2xqYVhCaGJuUmZjMlYwSWpvaWNERWlMQWtKRFFvaVkyOXVjMlZ1ZEY5bmNtOTFjQ0k2SW1NNU9Ua2lMQTBLSW5KdmJHVWlPaUp3YVNJc0RRb2laWGh3YVhKaGRHbHZiaUk2TVRZME1UQXhNekl3TUFrTkNuME5DaUFnSUNBZ1hTQU5DbjAuTnpSOEtzZTJOOUtFOXhvLUo4dXdUaWxzUG9pYXhNWGlGR0prY0JOYTMtOGt1ZEh3MFd6U0xDM3Z3Qk4yZ3Z0RUtMZ2ZBeVpVUDZrc0ktRzlOV0NIU3Z2RG4tbFNhbjVtV1dfWEhrRVdGWGd3RXotWlNNalBvV0Vndlk1bHhSWEhxR1lhWmQ5U2puTjdsTFpUbHNQLU9pbFUxcUNyQ205YzVfcTh1YWJyZ3o0OW5PWFRGZEpKblpPT1ZzUmtkU0NjVnlHczRlbUxNSjdDdVd2ckU2RkR2Ri1QTUpGNlhHYnN3R1pjVFRPM3h0MjR6Tk1wbm5RUEVzNXQ3Tk1LZjhucEJ3czNvd0FKcklTRkExYTNmUWtJZU83dFRUUGVSX1FRVUlxYzFJRW5JdlotMGdsNE5ETEZRSjJTTS1KdUtvSWdnQWt3NVNGWDNhSk9WNC12b2JZbXhBIl0NCn0.sJwAZeR8cYyF-BCluC9fmiQAi14L7hC3DB4MoFQNNdoakUBujPZ-NlpfP2rBgJQ3CGcxsF95Vdczm6Yk4TKa68eXkKjkswjsSSQg0qErgFhN2jis9KMxnMfmfPNUfb0lioHtD-_oghRkd9239oUwLR06KB5Ux3mD4Pc0ZPbJxJcPmyP9DZ8WEHmAFIJpcoayHwJDr1jt-GbqUtaTCs1VQ9Habh8Z8fvwrlvQNj744m5eq6141bD0G15KgvbyYf9L4_PYNgMjTyUx9EGyetrxQ4XmOpDF_ZbFEhZliy80qfO2HGQzSId-dKXCvPI_SUWcCVeJqPwmXTirTt9qJ63ypw";

    // Passport with two visas: LinkedIdentities (no ras_dbgap_permissions) + RAS dbGaP (with 2 permissions)
    private static final String multiVisaPassportWithPermissions = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0"
            + ".eyJzdWIiOiJ0ZXN0LXN1Yi0wMDEiLCJqdGkiOiJwYXNzcG9ydC1qdGktMDAxIiwic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEiLCJ0eG4iOiJ0ZXN0LXR4bi0wMDEiLCJpc3MiOiJodHRwczovL3N0c3N0Zy5uaWguZ292IiwiaWF0IjoxNjIwMjEwMzYyLCJleHAiOjE2MjAyNTM1NjIsImdhNGdoX3Bhc3Nwb3J0X3YxIjpbImV5SjBlWEFpT2lKS1YxUWlMQ0poYkdjaU9pSlNVekkxTmlJc0ltdHBaQ0k2SW5SbGMzUXRhMlY1SW4wLmV5SnBjM01pT2lKb2RIUndjem92TDNOMGMzTjBaeTV1YVdndVoyOTJJaXdpYzNWaUlqb2lkR1Z6ZEMxemRXSXRNREF4SWl3aWFXRjBJam94TmpJd01qRXdNell5TENKbGVIQWlPakUyTWpBeU5UTTFOaklzSW5OamIzQmxJam9pYjNCbGJtbGtJR2RoTkdkb1gzQmhjM053YjNKMFgzWXhJaXdpYW5ScElqb2lkbWx6WVMxcWRHa3RiR2x1YTJWa0xUQXdNU0lzSW5SNGJpSTZJblJsYzNRdGRIaHVMVEF3TVNJc0ltZGhOR2RvWDNacGMyRmZkakVpT25zaWRIbHdaU0k2SWt4cGJtdGxaRWxrWlc1MGFYUnBaWE1pTENKaGMzTmxjblJsWkNJNk1UWXlNREl4TURNMk1pd2lkbUZzZFdVaU9pSjBaWE4wTFd4cGJtdGxaQzFwWkMxMllXeDFaU0lzSW5OdmRYSmpaU0k2SW1oMGRIQnpPaTh2YzNSemMzUm5MbTVwYUM1bmIzWWlMQ0ppZVNJNkltNXBhQzVuYjNZaWZYMC5mYWtlc2lnbmF0dXJlIiwiZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJblJsYzNRdGEyVjVJbjAuZXlKcGMzTWlPaUpvZEhSd2N6b3ZMM04wYzNOMFp5NXVhV2d1WjI5Mklpd2ljM1ZpSWpvaWRHVnpkQzF6ZFdJdE1EQXhJaXdpYVdGMElqb3hOakl3TWpFd016WXlMQ0psZUhBaU9qRTJNakF5TlRNMU5qSXNJbk5qYjNCbElqb2liM0JsYm1sa0lHZGhOR2RvWDNCaGMzTndiM0owWDNZeElpd2lhblJwSWpvaWRtbHpZUzFxZEdrdFpHSm5ZWEF0TURBeElpd2lkSGh1SWpvaWRHVnpkQzEwZUc0dE1EQXhJaXdpWjJFMFoyaGZkbWx6WVY5Mk1TSTZleUowZVhCbElqb2lhSFIwY0hNNkx5OXlZWE11Ym1sb0xtZHZkaTkyYVhOaGN5OTJNUzR4SWl3aVlYTnpaWEowWldRaU9qRTJNakF5TVRBek5qSXNJblpoYkhWbElqb2lhSFIwY0hNNkx5OXpkSE56ZEdjdWJtbG9MbWR2ZGk5d1lYTnpjRzl5ZEM5a1ltZGhjQzkyTVM0eElpd2ljMjkxY21ObElqb2lhSFIwY0hNNkx5OXVZMkpwTG01c2JTNXVhV2d1WjI5MkwyZGhjQ0lzSW1KNUlqb2laR0ZqSW4wc0luSmhjMTlrWW1kaGNGOXdaWEp0YVhOemFXOXVjeUk2VzNzaVkyOXVjMlZ1ZEY5dVlXMWxJam9pUjJWdVpYSmhiQ0JTWlhObFlYSmphQ0JWYzJVaUxDSndhSE5mYVdRaU9pSndhSE13TURBd01EY2lMQ0oyWlhKemFXOXVJam9pZGpNeklpd2ljR0Z5ZEdsamFYQmhiblJmYzJWMElqb2ljREVpTENKamIyNXpaVzUwWDJkeWIzVndJam9pWXpFaUxDSnliMnhsSWpvaWNHa2lMQ0psZUhCcGNtRjBhVzl1SWpveE5qUXhNREV6TWpBd2ZTeDdJbU52Ym5ObGJuUmZibUZ0WlNJNklraGxZV3gwYUNCTlpXUnBZMkZzSUVKcGIyMWxaR2xqWVd3aUxDSndhSE5mYVdRaU9pSndhSE13TURBeE56a2lMQ0oyWlhKemFXOXVJam9pZGpnaUxDSndZWEowYVdOcGNHRnVkRjl6WlhRaU9pSndNaUlzSW1OdmJuTmxiblJmWjNKdmRYQWlPaUpqTWlJc0luSnZiR1VpT2lKd2FTSXNJbVY0Y0dseVlYUnBiMjRpT2pFMk5ERXdNVE15TURCOVhYMC5mYWtlc2lnbmF0dXJlIl19"
            + ".fakesignature";

    // Passport with two visas: LinkedIdentities (no ras_dbgap_permissions) + RAS dbGaP (empty permissions)
    private static final String multiVisaPassportWithEmptyPermissions = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0"
            + ".eyJzdWIiOiJ0ZXN0LXN1Yi0wMDEiLCJqdGkiOiJwYXNzcG9ydC1qdGktMDAyIiwic2NvcGUiOiJvcGVuaWQgZ2E0Z2hfcGFzc3BvcnRfdjEiLCJ0eG4iOiJ0ZXN0LXR4bi0wMDEiLCJpc3MiOiJodHRwczovL3N0c3N0Zy5uaWguZ292IiwiaWF0IjoxNjIwMjEwMzYyLCJleHAiOjE2MjAyNTM1NjIsImdhNGdoX3Bhc3Nwb3J0X3YxIjpbImV5SjBlWEFpT2lKS1YxUWlMQ0poYkdjaU9pSlNVekkxTmlJc0ltdHBaQ0k2SW5SbGMzUXRhMlY1SW4wLmV5SnBjM01pT2lKb2RIUndjem92TDNOMGMzTjBaeTV1YVdndVoyOTJJaXdpYzNWaUlqb2lkR1Z6ZEMxemRXSXRNREF4SWl3aWFXRjBJam94TmpJd01qRXdNell5TENKbGVIQWlPakUyTWpBeU5UTTFOaklzSW5OamIzQmxJam9pYjNCbGJtbGtJR2RoTkdkb1gzQmhjM053YjNKMFgzWXhJaXdpYW5ScElqb2lkbWx6WVMxcWRHa3RiR2x1YTJWa0xUQXdNU0lzSW5SNGJpSTZJblJsYzNRdGRIaHVMVEF3TVNJc0ltZGhOR2RvWDNacGMyRmZkakVpT25zaWRIbHdaU0k2SWt4cGJtdGxaRWxrWlc1MGFYUnBaWE1pTENKaGMzTmxjblJsWkNJNk1UWXlNREl4TURNMk1pd2lkbUZzZFdVaU9pSjBaWE4wTFd4cGJtdGxaQzFwWkMxMllXeDFaU0lzSW5OdmRYSmpaU0k2SW1oMGRIQnpPaTh2YzNSemMzUm5MbTVwYUM1bmIzWWlMQ0ppZVNJNkltNXBhQzVuYjNZaWZYMC5mYWtlc2lnbmF0dXJlIiwiZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJblJsYzNRdGEyVjVJbjAuZXlKcGMzTWlPaUpvZEhSd2N6b3ZMM04wYzNOMFp5NXVhV2d1WjI5Mklpd2ljM1ZpSWpvaWRHVnpkQzF6ZFdJdE1EQXhJaXdpYVdGMElqb3hOakl3TWpFd016WXlMQ0psZUhBaU9qRTJNakF5TlRNMU5qSXNJbk5qYjNCbElqb2liM0JsYm1sa0lHZGhOR2RvWDNCaGMzTndiM0owWDNZeElpd2lhblJwSWpvaWRtbHpZUzFxZEdrdFpHSm5ZWEF0Wlcxd2RIa3RNREF4SWl3aWRIaHVJam9pZEdWemRDMTBlRzR0TURBeElpd2laMkUwWjJoZmRtbHpZVjkyTVNJNmV5SjBlWEJsSWpvaWFIUjBjSE02THk5eVlYTXVibWxvTG1kdmRpOTJhWE5oY3k5Mk1TNHhJaXdpWVhOelpYSjBaV1FpT2pFMk1qQXlNVEF6TmpJc0luWmhiSFZsSWpvaWFIUjBjSE02THk5emRITnpkR2N1Ym1sb0xtZHZkaTl3WVhOemNHOXlkQzlrWW1kaGNDOTJNUzR4SWl3aWMyOTFjbU5sSWpvaWFIUjBjSE02THk5dVkySnBMbTVzYlM1dWFXZ3VaMjkyTDJkaGNDSXNJbUo1SWpvaVpHRmpJbjBzSW5KaGMxOWtZbWRoY0Y5d1pYSnRhWE56YVc5dWN5STZXMTE5LmZha2VzaWduYXR1cmUiXX0"
            + ".fakesignature";

    @Test
    public void testValidateUserPassport_invalidatesWhenAnyVisaIsInvalid() {
        long future = (System.currentTimeMillis() / 1000) + 100_000;
        String visa1 = visaJwt(future, "visa-one");
        String visa2 = visaJwt(future, "visa-two");
        assertNotEquals(visa1, visa2, "test visas must be distinct so per-visa stubbing is meaningful");
        String passport = passportJwt(future, visa1, visa2);

        RASPassPortService svc = spy(new RASPassPortService(restClientUtil, userService, "https://test.com/", cacheEvictionService, null));
        // First visa validates, second does not. The whole passport must be invalidated.
        doReturn(Optional.of(PassportValidationResponse.VALID.getValue())).when(svc).validateVisa(visa1);
        doReturn(Optional.of(PassportValidationResponse.INVALID.getValue())).when(svc).validateVisa(visa2);

        User user = new User();
        user.setSubject("test-subject");
        user.setPassport(passport);

        RASPassPortService.ValidationOutcome outcome = svc.validateUserPassport(user);

        assertEquals(RASPassPortService.ValidationOutcome.INVALIDATED, outcome,
                "A passport with any invalid visa must be invalidated, not validated after the first visa");
        verify(svc).validateVisa(visa2);
    }

    @Test
    public void testValidateUserPassport_validatesEveryVisaWhenAllValid() {
        long future = (System.currentTimeMillis() / 1000) + 100_000;
        String visa1 = visaJwt(future, "visa-one");
        String visa2 = visaJwt(future, "visa-two");
        String passport = passportJwt(future, visa1, visa2);

        RASPassPortService svc = spy(new RASPassPortService(restClientUtil, userService, "https://test.com/", cacheEvictionService, null));
        doReturn(Optional.of(PassportValidationResponse.VALID.getValue())).when(svc).validateVisa(visa1);
        doReturn(Optional.of(PassportValidationResponse.VALID.getValue())).when(svc).validateVisa(visa2);

        User user = new User();
        user.setSubject("test-subject");
        user.setPassport(passport);

        RASPassPortService.ValidationOutcome outcome = svc.validateUserPassport(user);

        assertEquals(RASPassPortService.ValidationOutcome.VALIDATED, outcome);
        // Every visa must be validated, not just the first.
        verify(svc).validateVisa(visa1);
        verify(svc).validateVisa(visa2);
    }

    private static String visaJwt(long exp, String id) {
        String payload = "{\"iss\":\"https://stsstg.nih.gov\",\"exp\":" + exp + ",\"jti\":\"" + id + "\","
                + "\"ga4gh_visa_v1\":{\"type\":\"https://ras.nih.gov/visas/v1.1\",\"value\":\"v\",\"source\":\"s\",\"by\":\"dac\"}}";
        return standardB64Jwt(payload);
    }

    private static String passportJwt(long exp, String... visas) {
        StringBuilder arr = new StringBuilder("[");
        for (int i = 0; i < visas.length; i++) {
            if (i > 0) arr.append(",");
            arr.append("\"").append(visas[i]).append("\"");
        }
        arr.append("]");
        String payload = "{\"iss\":\"https://stsstg.nih.gov\",\"exp\":" + exp + ",\"iat\":" + (exp - 200_000)
                + ",\"ga4gh_passport_v1\":" + arr + "}";
        return standardB64Jwt(payload);
    }

    // Build header.payload.signature using STANDARD base64, matching the decoder JWTUtil uses to parse.
    private static String standardB64Jwt(String payloadJson) {
        String header = b64("{\"alg\":\"RS256\",\"kid\":\"k\"}");
        return header + "." + b64(payloadJson) + ".signature";
    }

    private static String b64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void testValidateVisa_transportError_returnsEmpty() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenThrow(new RuntimeException("connection refused"));

        Optional<String> response = rasPassPortService.validateVisa(visa);

        assertTrue(response.isEmpty(),
                "A transport error must return empty (skip), not a 'Visa Expired' verdict that logs the user out");
    }

    @Test
    public void testValidateUserPassport_transientRasError_doesNotLogOut() {
        long future = (System.currentTimeMillis() / 1000) + 100_000;
        String passport = passportJwt(future, visaJwt(future, "visa-one"));
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenThrow(new RuntimeException("RAS unreachable"));

        RASPassPortService svc = new RASPassPortService(restClientUtil, userService, "https://test.com/", cacheEvictionService, null);
        User user = new User();
        user.setSubject("test-subject");
        user.setPassport(passport);

        RASPassPortService.ValidationOutcome outcome = svc.validateUserPassport(user);

        assertEquals(RASPassPortService.ValidationOutcome.SKIPPED, outcome,
                "A transient RAS validation error must not invalidate the passport");
        verify(userService, never()).logoutUser(any());
    }

    @Test
    public void testParsePassport_absentGa4ghPassportV1_isEmptyNotNull() {
        long future = (System.currentTimeMillis() / 1000) + 100_000;
        String payload = "{\"iss\":\"https://stsstg.nih.gov\",\"exp\":" + future + "}";
        Optional<Passport> parsed = JWTUtil.parsePassportJWTV11(standardB64Jwt(payload));

        assertTrue(parsed.isPresent());
        assertNotNull(parsed.get().getGa4ghPassportV1(), "missing ga4gh_passport_v1 must yield an empty list, not null");
        assertTrue(parsed.get().getGa4ghPassportV1().isEmpty());
    }

    @Test
    public void testValidateUserPassport_passportWithNoVisas_skipsWithoutNpe() {
        long future = (System.currentTimeMillis() / 1000) + 100_000;
        String payload = "{\"iss\":\"https://stsstg.nih.gov\",\"exp\":" + future + ",\"iat\":" + (future - 200_000) + "}";
        String passport = standardB64Jwt(payload);

        RASPassPortService svc = spy(new RASPassPortService(restClientUtil, userService, "https://test.com/", cacheEvictionService, null));
        User user = new User();
        user.setSubject("test-subject");
        user.setPassport(passport);

        RASPassPortService.ValidationOutcome outcome = svc.validateUserPassport(user);

        assertEquals(RASPassPortService.ValidationOutcome.SKIPPED, outcome,
                "A passport with no ga4gh_passport_v1 visas must skip cleanly, not NPE");
        verify(svc, never()).validateVisa(any());
    }

    @Test
    public void testIsExpired_passportPastExpirationIsExpiredRegardlessOfIssuedAt() {
        long now = System.currentTimeMillis() / 1000;
        Passport passport = new Passport();
        passport.setExp(now - 100_000); // already expired
        passport.setIat(now + 100_000); // malformed / future issued-at must not mask expiry

        assertTrue(rasPassPortService.isExpired(passport),
                "A passport past its exp must be reported expired even when iat is not in the past");
    }

    @Test
    public void testIsExpired_validPassportIsNotExpired() {
        long now = System.currentTimeMillis() / 1000;
        Passport passport = new Passport();
        passport.setExp(now + 100_000); // not yet expired
        passport.setIat(now - 100_000);

        assertFalse(rasPassPortService.isExpired(passport),
                "A passport whose exp is in the future must not be reported expired");
    }

    @Test
    public void testGa4ghPassPortStudies_IsNull() {
        Set<RasDbgapPermission> permissions = rasPassPortService.ga4ghPassportToRasDbgapPermissions(null);
        assertNull(permissions);
    }

    @Test
    public void testGa4gpPassportStudies_IsNotNull_And_ExpiredPermissionsExcluded() {
        Optional<Passport> passport = JWTUtil.parsePassportJWTV11(exampleRasPassport);
        Set<Optional<Ga4ghPassportV1>> ga4ghPassports = passport.get().getGa4ghPassportV1().stream().map(JWTUtil::parseGa4ghPassportV1).filter(Optional::isPresent).collect(Collectors.toSet());
        Set<RasDbgapPermission> permissions = rasPassPortService.ga4ghPassportToRasDbgapPermissions(ga4ghPassports);
        assertNotNull(permissions);
        assertTrue(permissions.isEmpty());
    }

    @Test
    public void testGa4gpPassportStudies_HasCorrectStudies() {
        Optional<Passport> passport = JWTUtil.parsePassportJWTV11(exampleRasPassport);
        long futureDate = (Instant.now().toEpochMilli() / 1000) + 100000;

        // Update the expiry date of each permission in our test passport. All permissions in the example passport
        // expired in 2022.
        Set<Optional<Ga4ghPassportV1>> ga4ghPassports = passport.get().getGa4ghPassportV1().stream()
                .map(JWTUtil::parseGa4ghPassportV1)
                .filter(Optional::isPresent)
                .map(optionalPassport -> {
                    Ga4ghPassportV1 ga4ghPassportV1 = optionalPassport.get();
                    List<RasDbgapPermission> rasDbgapPermissions = ga4ghPassportV1.getRasDbgagPermissions();
                    List<RasDbgapPermission> newExpires = rasDbgapPermissions.stream().peek(rasDbgapPermission -> rasDbgapPermission.setExpiration(futureDate)).toList();
                    ga4ghPassportV1.setRasDbgapPermissions(newExpires);
                    return Optional.of(ga4ghPassportV1);
                })
                .collect(Collectors.toSet());

        Set<RasDbgapPermission> permissions = rasPassPortService.ga4ghPassportToRasDbgapPermissions(ga4ghPassports);

        assertEquals(2, permissions.size());
        assertTrue(permissions.stream().anyMatch(p -> p.getPhsId().equals("phs000300")));
        assertTrue(permissions.stream().anyMatch(p -> p.getPhsId().equals("phs000006")));
    }

    @Test
    public void testGa4gpPassportStudies_HalfAreExpired() {
        Optional<Passport> passport = JWTUtil.parsePassportJWTV11(exampleRasPassport);
        long futureDate = (Instant.now().toEpochMilli() / 1000) + 100000;
        long pastDate = (Instant.now().toEpochMilli() / 1000) - 100000;

        List<String> expiredPHS = new ArrayList<>();
        List<String> validPHS = new ArrayList<>();
        // Update the expiry date of each permission in our test passport.
        // We alternate: even-indexed permissions become valid, odd-indexed ones remain (or become) invalid.
        Set<Optional<Ga4ghPassportV1>> ga4ghPassports = passport.get().getGa4ghPassportV1().stream()
                .map(JWTUtil::parseGa4ghPassportV1)
                .filter(Optional::isPresent)
                .map(optionalPassport -> {
                    Ga4ghPassportV1 ga4ghPassportV1 = optionalPassport.get();
                    List<RasDbgapPermission> rasDbgapPermissions = ga4ghPassportV1.getRasDbgagPermissions();

                    AtomicInteger index = new AtomicInteger();
                    List<RasDbgapPermission> updatedPermissions = rasDbgapPermissions.stream()
                            .peek(permission -> {
                                if (index.getAndIncrement() % 2 == 0) {
                                    // For even indices, use a valid future expiration.
                                    permission.setExpiration(futureDate);
                                    validPHS.add(permission.getPhsId());
                                } else {
                                    // For odd indices, use an expired (invalid) timestamp.
                                    permission.setExpiration(pastDate);
                                    expiredPHS.add(permission.getPhsId());
                                }
                            })
                            .collect(Collectors.toList());

                    ga4ghPassportV1.setRasDbgapPermissions(updatedPermissions);
                    return Optional.of(ga4ghPassportV1);
                })
                .collect(Collectors.toSet());

        // Convert the GA4GH passports to RAS DbGaP permissions. The underlying conversion
        // should filter out the ones with invalid expiration dates.
        Set<RasDbgapPermission> permissions = rasPassPortService.ga4ghPassportToRasDbgapPermissions(ga4ghPassports);

        // We expect only the valid (future-dated) permissions to be returned.
        assertEquals(validPHS.size(), permissions.size());

        // verify only expected values are in permissions set
        List<String> finalPHS = permissions.stream().map(RasDbgapPermission::getPhsId).toList();
        assertEquals(finalPHS, validPHS, "The valid phs ids do not match the expected values.");

        // verify no expired permissions are in the passport.
        expiredPHS.forEach(phs -> assertFalse(finalPHS.contains(phs), "Expired phs id " + phs + " should not appear in the valid permissions."));
    }


    @Test
    public void testValidateVisa_Valid() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("Valid", HttpStatus.OK));
        Optional<String> response = rasPassPortService.validateVisa(visa);
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.VALID.getValue(), response.get());
    }

    @Test
    public void testValidateVisa_Invalid() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("Invalid", HttpStatus.OK));
        Optional<String> response = rasPassPortService.validateVisa(visa);
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.INVALID.getValue(), response.get());
    }

    @Test
    public void testValidateVisa_Missing() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("Missing", HttpStatus.OK));
        Optional<String> response = rasPassPortService.validateVisa(visa);
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.MISSING.getValue(), response.get());
    }

    @Test
    public void testValidatePassport_InvalidVisa() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("Invalid Passport", HttpStatus.OK));
        Optional<String> response = rasPassPortService.validateVisa(visa);
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.INVALID_PASSPORT.getValue(), response.get());
    }

    @Test
    public void testValidateVisa_VisaExpired() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("Visa Expired", HttpStatus.OK));
        Optional<String> response = rasPassPortService.validateVisa(visa);
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.VISA_EXPIRED.getValue(), response.get());
    }

    @Test
    public void testValidateVisa_TxnError() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("Txn Error", HttpStatus.OK));
        Optional<String> response = rasPassPortService.validateVisa(visa);
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.TXN_ERROR.getValue(), response.get());
    }

    @Test
    public void testValidateVisa_ExpirationError() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("Expiration Error", HttpStatus.OK));
        Optional<String> response = rasPassPortService.validateVisa(visa);
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.EXPIRATION_ERROR.getValue(), response.get());
    }

    @Test
    public void testValidateVisa_ValidationError() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("Validation Error", HttpStatus.OK));
        Optional<String> response = rasPassPortService.validateVisa(visa);
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.VALIDATION_ERROR.getValue(), response.get());
    }

    @Test
    public void testValidateVisa_ExpiredPolling() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("Expired Polling", HttpStatus.OK));
        Optional<String> response = rasPassPortService.validateVisa(visa);
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.EXPIRED_POLLING.getValue(), response.get());
    }

    @Test
    public void testValidateVisa_PermissionUpdate() {
        when(restClientUtil.retrievePostResponse(any(String.class), any()))
                .thenReturn(new ResponseEntity<>("Permission Update", HttpStatus.OK));
        Optional<String> response = rasPassPortService.validateVisa(visa);
        assertTrue(response.isPresent());
        assertEquals(PassportValidationResponse.PERMISSION_UPDATE.getValue(), response.get());
    }

    @Test
    public void testMultiVisaPassport_LinkedIdentitiesVisaHasNoPermissions_DoesNotThrowNPE() {
        Optional<Passport> passport = JWTUtil.parsePassportJWTV11(multiVisaPassportWithEmptyPermissions);
        assertTrue(passport.isPresent());
        assertEquals(2, passport.get().getGa4ghPassportV1().size());

        Set<Optional<Ga4ghPassportV1>> ga4ghPassports = passport.get().getGa4ghPassportV1().stream()
                .map(JWTUtil::parseGa4ghPassportV1)
                .filter(Optional::isPresent)
                .collect(Collectors.toSet());

        // Should not throw NPE even though LinkedIdentities visa has no ras_dbgap_permissions
        Set<RasDbgapPermission> permissions = rasPassPortService.ga4ghPassportToRasDbgapPermissions(ga4ghPassports);
        assertNotNull(permissions);
        assertTrue(permissions.isEmpty());
    }

    @Test
    public void testMultiVisaPassport_WithPermissions_ReturnsCorrectStudies() {
        Optional<Passport> passport = JWTUtil.parsePassportJWTV11(multiVisaPassportWithPermissions);
        assertTrue(passport.isPresent());
        assertEquals(2, passport.get().getGa4ghPassportV1().size());

        long futureDate = (Instant.now().toEpochMilli() / 1000) + 100000;

        Set<Optional<Ga4ghPassportV1>> ga4ghPassports = passport.get().getGa4ghPassportV1().stream()
                .map(JWTUtil::parseGa4ghPassportV1)
                .filter(Optional::isPresent)
                .map(optionalPassport -> {
                    Ga4ghPassportV1 ga4ghPassportV1 = optionalPassport.get();
                    List<RasDbgapPermission> rasDbgapPermissions = ga4ghPassportV1.getRasDbgagPermissions();
                    List<RasDbgapPermission> newExpires = rasDbgapPermissions.stream()
                            .peek(rasDbgapPermission -> rasDbgapPermission.setExpiration(futureDate))
                            .toList();
                    ga4ghPassportV1.setRasDbgapPermissions(newExpires);
                    return Optional.of(ga4ghPassportV1);
                })
                .collect(Collectors.toSet());

        Set<RasDbgapPermission> permissions = rasPassPortService.ga4ghPassportToRasDbgapPermissions(ga4ghPassports);

        // Only the dbGaP visa has permissions - LinkedIdentities visa has none
        assertEquals(2, permissions.size());
        assertTrue(permissions.stream().anyMatch(p -> p.getPhsId().equals("phs000007")));
        assertTrue(permissions.stream().anyMatch(p -> p.getPhsId().equals("phs000179")));
    }

}