package edu.harvard.hms.dbmi.avillach.auth.utils;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Contains all preset PSAMA naming conventions.</p>
 */
public class AuthNaming {

    public static final String LONG_TERM_TOKEN_PREFIX = "LONG_TERM_TOKEN";
    public static final String PSAMA_APPLICATION_TOKEN_PREFIX = "PSAMA_APPLICATION";

    /**
     * <p>Contains all preset PSAMA role naming conventions.</p>
     * <p>Note: Only users with super admin access can edit these role names.</p>
     */
    public static class AuthRoleNaming {
        public static final String ADMIN = "ADMIN";
        public static final String SUPER_ADMIN = "SUPER_ADMIN";

        public static List<String> allRoles(){
            List<String> roles = new ArrayList<>();
            for (Field field : AuthRoleNaming.class.getFields()){
                roles.add(field.getName());
            }
            return roles;
        }
    }
}
