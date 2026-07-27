package edu.harvard.hms.dbmi.avillach.auth.rest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.hms.dbmi.avillach.auth.entity.UserConsents;
import edu.harvard.hms.dbmi.avillach.auth.exceptions.GlobalExceptionHandler;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Standalone MockMvc tests: exercise real request-mapping and argument resolution, which plain
 * controller unit tests bypass (a stray @PathVariable only fails when the mapping is exercised).
 */
public class UserControllerWebTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private MockMvc mockMvc;
    private UserService userService;

    @BeforeEach
    public void setUp() {
        userService = Mockito.mock(UserService.class);
        UserController controller = new UserController(userService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).setControllerAdvice(new GlobalExceptionHandler()).build();
    }

    @Test
    public void getUserConsents_withConsents_returns200WithConsentsMap() throws Exception {
        UserConsents userConsents = new UserConsents()
            .setUserId(UUID.randomUUID())
            .setConsents(Map.of("\\_consents\\", Set.of("phs1234.c1")));
        when(userService.getUserConsents()).thenReturn(userConsents);

        MvcResult result = mockMvc.perform(get("/user/me/consents")).andExpect(status().isOk()).andReturn();

        JsonNode consents = MAPPER.readTree(result.getResponse().getContentAsString()).get("consents");
        assertNotNull(consents);
        JsonNode studies = consents.get("\\_consents\\");
        assertNotNull(studies);
        assertEquals(1, studies.size());
        assertEquals("phs1234.c1", studies.get(0).asText());
    }

    @Test
    public void getUserConsents_noConsentsRow_returns200WithEmptyConsentsMap() throws Exception {
        when(userService.getUserConsents()).thenReturn(new UserConsents().setUserId(UUID.randomUUID()).setConsents(Map.of()));

        MvcResult result = mockMvc.perform(get("/user/me/consents")).andExpect(status().isOk()).andReturn();

        JsonNode consents = MAPPER.readTree(result.getResponse().getContentAsString()).get("consents");
        assertNotNull(consents);
        assertTrue(consents.isObject());
        assertTrue(consents.isEmpty());
    }

    @Test
    public void getUserConsents_noUsablePrincipal_returns500() throws Exception {
        when(userService.getUserConsents()).thenReturn(null);

        mockMvc.perform(get("/user/me/consents")).andExpect(status().isInternalServerError());
    }
}
