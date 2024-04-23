package edu.harvard.hms.dbmi.avillach.auth.security;

import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;

import java.security.Principal;

/**
 * <p>Implements the SecurityContext interface for JWTFilter to use.</p>
 */
public class AuthSecurityContext implements SecurityContext {

    private User user;
    private Application application;

    public AuthSecurityContext(User user, String scheme) {
        this.user = user;
    }

    public AuthSecurityContext(Application application, String scheme) {
        this.application = application;
    }

    public Principal getUserPrincipal() {
        return this.user == null ? this.application : this.user;
    }

    public boolean isUserInRole(String role) {
        if (user.getRoles() != null)
            return user.getPrivilegeNameSet().contains(role);
        return false;
    }

    @Override
    public Authentication getAuthentication() {
        return null;
    }

    @Override
    public void setAuthentication(Authentication authentication) {

    }
}
