package edu.harvard.hms.dbmi.avillach.auth.model;

import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class CustomApplicationDetails implements UserDetails {

    private final Collection<? extends GrantedAuthority> authorities;

    public CustomApplicationDetails(Application authenticatedApplication) {
        if (authenticatedApplication == null) {
            throw new IllegalArgumentException("Application cannot be null");
        }

        this.authorities = authenticatedApplication.getPrivileges().stream()
                .map(privilege -> (GrantedAuthority) privilege::getName)
                .toList();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return "";
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
}
