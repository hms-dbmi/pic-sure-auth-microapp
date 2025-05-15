package edu.harvard.hms.dbmi.avillach.auth.entity;

import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.persistence.*;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * <p>Models the authorization layer along with Privilege/AccessRule.</p>
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@Entity(name = "role")
public class Role extends BaseEntity {

    private String name;

    private String description;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "role_privilege",
            joinColumns = {@JoinColumn(name = "role_id")},
            inverseJoinColumns = {@JoinColumn(name = "privilege_id")})
    private Set<Privilege> privileges;

    private int version;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Set<Privilege> getPrivileges() {
        return privileges;
    }

    public void setPrivileges(Set<Privilege> privileges) {
        this.privileges = privileges;
    }

    public int getRoleVersion() {
        return version;
    }

    public void setRoleVersion(int roleVersion) {
        this.version = roleVersion;
    }

    public String toString() {
    		return uuid.toString() + " ___ " + name + " ___ " + description + " ___ " + version + " ___(" + (privileges==null?"NO PRIVILEGES DEFINED":privileges.stream().map(Privilege::toString).collect(Collectors.joining("},{"))) + ")";
    }

}
