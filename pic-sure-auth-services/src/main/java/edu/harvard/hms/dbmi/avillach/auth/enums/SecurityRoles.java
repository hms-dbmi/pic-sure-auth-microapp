package edu.harvard.hms.dbmi.avillach.auth.enums;

import java.util.Set;

public enum SecurityRoles {

    ADMIN("ADMIN"),
    SUPER_ADMIN("SUPER_ADMIN"),
    PIC_SURE_TOP_ADMIN("PIC-SURE Top Admin");

    private final String role;

    SecurityRoles(String role) {
        this.role = role;
    }

    /**
     * Check if a role is contained in a set of roles
     *
     * @param roles User roles
     * @param role Role to check
     * @return True if the role is contained in the set of roles
     */
    public static boolean contains(Set<String> roles, String role) {
        return roles.contains(role);
    }

    public String getRole() {
        return role;
    }

}
