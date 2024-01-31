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
        /**
         * unit test for generateUserMetadata
         *protected ObjectNode generateUserMetadata (JsonNode introspectResponse, User user){
         *         // JsonNode is immutable, so we need to convert it to an ObjectNode
         *ObjectNode objectNode = JAXRSConfiguration.objectMapper.createObjectNode();
         *ObjectNode authzNode = objectNode.putObject("authz");
         *ObjectNode tagsNode = authzNode.putObject("tags");
         *
         *authzNode.put("role", "user");
         *authzNode.put("sub", introspectResponse.get("sub").asText());
         *authzNode.put("user_id", user.getUuid().toString());
         *authzNode.put("username", user.getEmail());
         *tagsNode.put("email", user.getEmail());
         *
         *return objectNode;
         *}
         *
         */

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

        assertEquals(result.get("authz").get("tags").get("email").asText(), email);
        assertEquals(result.get("authz").get("sub").asText(), "test_sub");
        assertEquals(result.get("authz").get("user_id").asText(), uuid.toString());
        assertEquals(result.get("authz").get("username").asText(), email);
        assertEquals(result.get("authz").get("role").asText(), "user");

        // print result
        System.out.println(result);
    }

}