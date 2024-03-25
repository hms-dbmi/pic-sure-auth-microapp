package edu.harvard.hms.dbmi.avillach.auth.enums;

import java.util.List;
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
        for (String r : roles) {
            if (r.equals(role)) {
                return true;
            }
        }
        return false;
    }

    public String getRole() {
        return role;
    }

    public static SecurityRoles getRole(String role) {
        for (SecurityRoles securityRole : SecurityRoles.values()) {
            if (securityRole.getRole().equals(role)) {
                return securityRole;
            }
        }
        return null;
    }

    public static boolean contains(String role) {
        for (SecurityRoles securityRole : SecurityRoles.values()) {
            if (securityRole.getRole().equals(role)) {
                return true;
            }
        }
        return false;
    }

    public static boolean contains(SecurityRoles role) {
        for (SecurityRoles securityRole : SecurityRoles.values()) {
            if (securityRole.equals(role)) {
                return true;
            }
        }
        return false;
    }

    public static boolean contains(List<String> roles) {
        for (String role : roles) {
            if (!contains(role)) {
                return false;
            }
        }
        return true;
    }

}
