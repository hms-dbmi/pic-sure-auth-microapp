package edu.harvard.hms.dbmi.avillach.auth.service.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.User;
import org.junit.Test;

import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

public class OktaOAuthAuthenticationServiceTest {

    private OktaOAuthAuthenticationService service;

    @Test
    public void testAuthenticate() {
    }

    @Test
    public void testGenerateUserMetadata() {
        //mock user
        UUID uuid = UUID.randomUUID();
        String email = "test_email@hms.harvard.edu";
        User user = org.mockito.Mockito.mock(User.class);
        when(user.getUuid()).thenReturn(uuid);
        when(user.getEmail()).thenReturn(email);

        //mock introspectResponse
        ObjectMapper objectMapper = new ObjectMapper();
        ObjectNode objectNode = objectMapper.createObjectNode();
        objectNode.put("sub", "test_sub");
        JsonNode introspectResponse = org.mockito.Mockito.mock(JsonNode.class);
        when(introspectResponse.get("sub")).thenReturn(objectNode.get("sub"));

        //test
        service = new OktaOAuthAuthenticationService();
        ObjectNode result = service.generateUserMetadata(introspectResponse, user);

        assertEquals(result.get("sub").asText(), "test_sub");
        assertEquals(result.get("user_id").asText(), uuid.toString());
        assertEquals(result.get("username").asText(), email);
        assertEquals(result.get("role").asText(), "user");

        // print result
        System.out.println(result);
    }

}