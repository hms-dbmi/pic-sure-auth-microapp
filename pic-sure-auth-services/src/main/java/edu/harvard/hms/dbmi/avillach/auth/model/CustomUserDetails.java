package edu.harvard.hms.dbmi.avillach.auth.model;

import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.enums.SecurityRoles;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class CustomUserDetails implements UserDetails {

    private final static Logger log = Logger.getLogger(CustomUserDetails.class.getName());
    private final User user;
    private final Collection<? extends GrantedAuthority> authorities;

    public CustomUserDetails(User user) {
        this.user = user;
        if (user != null && user.getRoles() != null) {
            List<GrantedAuthority> authorities = new ArrayList<>(user.getRoles().stream()
                    .map(role -> new SimpleGrantedAuthority(role.getName()))
                    .toList());

            if (authorities.stream().anyMatch(role -> role.getAuthority().equals(SecurityRoles.PIC_SURE_TOP_ADMIN.getRole()))) {
                authorities.add(new SimpleGrantedAuthority("ROLE_"+AuthNaming.AuthRoleNaming.ADMIN));
                authorities.add(new SimpleGrantedAuthority("ROLE_"+AuthNaming.AuthRoleNaming.SUPER_ADMIN));
            }

            this.authorities = authorities;
        } else {
            this.authorities = new ArrayList<>();
        }
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return this.user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public User getUser() {
        return user;
    }
}
