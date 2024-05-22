package edu.harvard.hms.dbmi.avillach.auth.data.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import edu.harvard.dbmi.avillach.data.entity.BaseEntity;
import org.hibernate.annotations.Type;

import javax.persistence.*;
import java.io.Serializable;
import java.security.Principal;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Defines a model of User behavior.
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@Entity(name = "user")
public class User extends BaseEntity implements Serializable, Principal {

	@Column(unique = true)
	private String subject;

	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "user_role", joinColumns = {
			@JoinColumn(name = "user_id", nullable = false, updatable = false) }, inverseJoinColumns = {
					@JoinColumn(name = "role_id", nullable = false, updatable = false) })
	private Set<Role> roles;

	private String email;

	/**
	 * <p>
	 * NOTICE
	 * </p>
	 * <br>
	 * <p>
	 * When you update or create a user, please use connection.id as the input. The
	 * UserService is specifically using connection.id.
	 * </p>
	 * <br>
	 * <p>
	 * <b> Note: This is because of the checkAssociation() method in UserService.
	 * </b>
	 * </p>
	 * <br>
	 * 
	 * @see edu.harvard.hms.dbmi.avillach.auth.rest.UserService
	 */
	@ManyToOne
	@JoinColumn(name = "connectionId")
	private Connection connection;

	private boolean matched;

	private Date acceptedTOS;

	@Column(name = "auth0_metadata")
	@Type(type = "text")
	private String auth0metadata;

	@Column(name = "general_metadata")
	@Type(type = "text")
	private String generalMetadata;

	@Column(name = "is_active")
	private boolean active = true;

	@Column(name = "long_term_token")
	private String token;

	public String getSubject() {
		return subject;
	}

	public User setSubject(String subject) {
		this.subject = subject;
		return this;
	}

	public Set<Role> getRoles() {
		return roles;
	}

	public User setRoles(Set<Role> roles) {
		this.roles = roles;
		return this;
	}

	/**
	 * return all privileges in the roles as a set
	 * 
	 * @return
	 */
	@JsonIgnore
	public Set<Privilege> getTotalPrivilege() {
		if (roles == null)
			return null;

		Set<Privilege> privileges = new HashSet<>();
		roles.stream().forEach(r -> privileges.addAll(r.getPrivileges()));
		return privileges;
	}

	/**
	 * return all privileges in the roles as a set
	 * 
	 * @return
	 */
	@JsonIgnore
	public Set<AccessRule> getTotalAccessRule() {
		if (roles == null)
			return null;

		Set<AccessRule> accessRules = new HashSet<>();
		roles.stream().forEach(r -> r.getPrivileges().stream().forEach(p -> accessRules.addAll(p.getAccessRules())));
		return accessRules;
	}

	/**
	 * return all privilege name in each role as a set.
	 *
	 * @return
	 */
	@JsonIgnore
	public Set<String> getPrivilegeNameSet() {
		Set<Privilege> totalPrivilegeSet = getTotalPrivilege();

		if (totalPrivilegeSet == null)
			return null;

		Set<String> nameSet = new HashSet<>();
		totalPrivilegeSet.stream().forEach(p -> nameSet.add(p.getName()));
		return nameSet;
	}

	/**
	 * return privilege names in each role as a set based on Application given.
	 *
	 * @return
	 */
	@JsonIgnore
	public Set<String> getPrivilegeNameSetByApplication(Application application) {
		Set<Privilege> totalPrivilegeSet = getTotalPrivilege();

		if (totalPrivilegeSet == null)
			return null;

		Set<String> nameSet = new HashSet<>();
		if (application == null)
			return nameSet;

		for (Privilege appPrivilege : application.getPrivileges()) {
			for (Privilege userPrivilege : totalPrivilegeSet) {
				if (appPrivilege.equals(userPrivilege))
					nameSet.add(userPrivilege.getName());
			}
		}
		return nameSet;
	}

	/**
	 * return privileges in each role as a set based on Application given.
	 *
	 * @return
	 */
	@JsonIgnore
	public Set<Privilege> getPrivilegesByApplication(Application application) {
		if (application == null || application.getUuid() == null) {
			return getTotalPrivilege();
		}

		if (roles == null)
			return null;

		Set<Privilege> privileges = new HashSet<>();
		roles.stream()
				.forEach(r -> privileges.addAll(r.getPrivileges().stream()
						.filter(p -> application.getUuid()
								.equals((p.getApplication() == null) ? null : p.getApplication().getUuid()))
						.collect(Collectors.toSet())));
		return privileges;
	}

	@JsonIgnore
	public String getPrivilegeString() {
		Set<Privilege> totalPrivilegeSet = getTotalPrivilege();

		if (totalPrivilegeSet == null)
			return null;

		return totalPrivilegeSet.stream().map(p -> p.getName()).collect(Collectors.joining(","));
	}

	@JsonIgnore
	public String getRoleString() {
		return (roles == null) ? null : roles.stream().map(r -> r.name).collect(Collectors.joining(","));
	}

	public String getAuth0metadata() {
		return auth0metadata;
	}

	public User setAuth0metadata(String auth0metadata) {
		this.auth0metadata = auth0metadata;
		return this;
	}

	public String getGeneralMetadata() {
		return generalMetadata;
	}

	public User setGeneralMetadata(String generalMetadata) {
		this.generalMetadata = generalMetadata;
		return this;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public Connection getConnection() {
		return connection;
	}

	public User setConnection(Connection connection) {
		this.connection = connection;
		return this;
	}

	public boolean isMatched() {
		return matched;
	}

	public void setMatched(boolean matched) {
		this.matched = matched;
	}

	public Date getAcceptedTOS() {
		return acceptedTOS;
	}

	public void setAcceptedTOS(Date acceptedTOS) {
		this.acceptedTOS = acceptedTOS;
	}

	@JsonIgnore
	@Override
	public String getName() {
		return this.subject;
	}

	public boolean isActive() {
		return active;
	}

	public void setActive(boolean active) {
		this.active = active;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	/**
	 * <p>
	 * Inner class defining limited user attributes returned from the User endpoint.
	 * </p>
	 */
	@JsonInclude(JsonInclude.Include.NON_EMPTY)
	public static class UserForDisplay {
		String uuid;
		String email;
		Set<String> privileges;
		String token;
		Set<String> queryScopes;
		private boolean acceptedTOS;

		public UserForDisplay() {
		}

		public String getEmail() {
			return email;
		}

		public UserForDisplay setEmail(String email) {
			this.email = email;
			return this;
		}

		public Set<String> getPrivileges() {
			return privileges;
		}

		public UserForDisplay setPrivileges(Set<String> privileges) {
			this.privileges = privileges;
			return this;
		}

		public String getUuid() {
			return uuid;
		}

		public UserForDisplay setUuid(String uuid) {
			this.uuid = uuid;
			return this;
		}

		public String getToken() {
			return token;
		}

		public UserForDisplay setToken(String token) {
			this.token = token;
			return this;
		}

		public Set<String> getQueryScopes() {
			return queryScopes;
		}

		public void setQueryScopes(Set<String> queryScopes) {
			this.queryScopes = queryScopes;
		}

		public boolean isAcceptedTOS() {
			return acceptedTOS;
		}

		public UserForDisplay setAcceptedTOS(boolean acceptedTOS) {
			this.acceptedTOS = acceptedTOS;
			return this;
		}
	}

	public String toString() {
		return uuid.toString() + " ___ " + subject + " ___ " + email + " ___ " + generalMetadata + " ___ "
				+ auth0metadata + " ___ {" + ((connection == null) ? null : connection.toString()) + "}";
	}
}
