package edu.harvard.hms.dbmi.avillach.auth.data.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import edu.harvard.dbmi.avillach.data.entity.BaseEntity;

import javax.persistence.*;
import java.util.Set;
import java.util.stream.Collectors;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@Entity(name = "privilege")
public class Privilege extends BaseEntity {

    @Column(unique = true)
    private String name;

    private String description;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "application_id")
    private Application application;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "accessRule_privilege",
            joinColumns = {@JoinColumn(name = "privilege_id")},
            inverseJoinColumns = {@JoinColumn(name = "accessRule_id")})
    private Set<AccessRule> accessRules;

    /**
     * We only support a JSON Object format for now,
     * since it will return a merged JSON in the end,
     * if saving as a JSON array, later processing will
     * throw exception
     */
    private String queryTemplate;

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

    @JsonIgnore
    public Application getApplication() {
        return application;
    }

    @JsonProperty("application")
    public void setApplication(Application application) {
        this.application = application;
    }

    public Set<AccessRule> getAccessRules() {
        return accessRules;
    }

    public void setAccessRules(Set<AccessRule> accessRules) {
        this.accessRules = accessRules;
    }

    public String getQueryTemplate() {
        return queryTemplate;
    }

    public void setQueryTemplate(String queryTemplate) {
        this.queryTemplate = queryTemplate;
    }

    @JsonProperty("application")
    public Application.ApplicationForDisplay getApplicationForDisplay(){
        if (application != null)
            return new Application.ApplicationForDisplay()
                .setDescription(application.getDescription())
                .setName(application.getName())
                .setEnable(application.isEnable())
                .setUuid(application.getUuid().toString());

        return null;
    }
    
    public String toString() {
    		return uuid.toString() + " ___ " + name + " ___ " + description + " ___ Application UUID : " + (application==null ? "NO APPLICATION AFFILIATED" : application.getUuid()) + "} ___ ({"+ (accessRules==null ? "NO ACCESS RULES DEFINED" :accessRules.stream().map(AccessRule::toString).collect(Collectors.joining("},{"))) + "})";
    }
}
