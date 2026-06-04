package edu.harvard.hms.dbmi.avillach.auth.entity;

import org.junit.jupiter.api.Test;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class UserClaimsTest {

    @Test
    public void toHashMap_includesFederatedIdentitiesIal2_whenSet() {
        UserClaims claims = new UserClaims();
        claims.setFederated_sources("{\"foo\":\"bar\"}");

        HashMap<String, Object> map = claims.toHashMap();

        assertEquals("{\"foo\":\"bar\"}", map.get("federated_identities_ial2"));
    }

    @Test
    public void toHashMap_omitsFederatedIdentitiesIal2_whenNull() {
        UserClaims claims = new UserClaims();

        HashMap<String, Object> map = claims.toHashMap();

        assertFalse(map.containsKey("federated_identities_ial2"));
    }
}
