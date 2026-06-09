package edu.harvard.hms.dbmi.avillach.auth.model.ras;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RasIal2UserInfo {

    /** Opaque pairwise subject identifier. Immutable per user+IDP. Primary mapping key. */
    @JsonProperty("sub")
    private String sub;

    /** Full display name. */
    @JsonProperty("name")
    private String name;

    /** Given name. May be absent for some IDPs below IAL2. */
    @JsonProperty("first_name")
    private String firstName;

    /** Family name. May be absent for some IDPs below IAL2. */
    @JsonProperty("last_name")
    private String lastName;

    /** Human-readable immutable id, format {@code idp_unique_identifier@idp_identifier}. */
    @JsonProperty("preferred_username")
    private String preferredUsername;

    /** IDP-side user id. NOT guaranteed immutable — do not use as a mapping key. */
    @JsonProperty("userid")
    private String userId;

    /** Email address. NOT immutable — do not use as a mapping key. */
    @JsonProperty("email")
    private String email;

    /** Organization, from the {@code source} scope. */
    @JsonProperty("company")
    private String company;

    /** Originating identity provider, from the {@code source} scope (e.g. {@code login.gov}). */
    @JsonProperty("source")
    private String source;

    /** Home organization / department, when released (primarily NIH). */
    @JsonProperty("department")
    private String department;

    /**
     * GA4GH passport: a list of encoded visa JWTs (compact JWS). Present when the
     * {@code ga4gh_passport_v1} scope is granted. Decode/validate separately — see class docs.
     */
    @JsonProperty("ga4gh_passport_v1")
    private List<String> ga4ghPassportV1;

    /**
     * Comma-delimited {@code role@institution} pairs linked from an eRA account, available at
     * IAL2 for Login.gov / ID.me / InCommon. (The plain {@code researcher_role} claim is eRA-only
     * and therefore never appears in an IAL2 response, since eRA cannot proof at IAL2.)
     */
    @JsonProperty("linked_era_role")
    private String linkedEraRole;

    /**
     * Comma-delimited {@code role@institution} pairs from the {@code researcher_role} scope.
     * Only released for direct eRA Commons logins; absent for all other IDPs. Non-blocking:
     * absence must never fail a login.
     */
    @JsonProperty("researcher_role")
    private String researcherRole;

    /**
     * IAL2 federated identities. Same shape as {@link #federatedIdentities} but only released to
     * CADRs / IAL2 systems, and Login.gov entries include first/last name since IAL2 is met.
     * Its presence is the in-payload signal that the user is identity-proofed at IAL2.
     */
    @JsonProperty("federated_identities_ial2")
    private FederatedIdentities federatedIdentitiesIal2;

    /** IAL1 federated identities (detailed: sources + per-IDP identity info). */
    @JsonProperty("federated_identities")
    private FederatedIdentities federatedIdentities;

    /**
     * High-level linked identity info for duplicate-account detection. Uses the same container
     * type for convenience, but RAS does not return an {@code identities} block here, so
     * {@link FederatedIdentities#getIdentities()} will be {@code null} for this field.
     */
    @JsonProperty("federated_sources")
    private FederatedIdentities federatedSources;

    public String getSub() { return sub; }
    public String getName() { return name; }
    public String getFirstName() { return firstName; }
    public String getLastName() { return lastName; }
    public String getPreferredUsername() { return preferredUsername; }
    public String getUserId() { return userId; }
    public String getEmail() { return email; }
    public String getCompany() { return company; }
    public String getSource() { return source; }
    public String getDepartment() { return department; }
    public List<String> getGa4ghPassportV1() { return ga4ghPassportV1; }
    public String getLinkedEraRole() { return linkedEraRole; }
    public String getResearcherRole() { return researcherRole; }
    public FederatedIdentities getFederatedIdentitiesIal2() { return federatedIdentitiesIal2; }
    public FederatedIdentities getFederatedIdentities() { return federatedIdentities; }
    public FederatedIdentities getFederatedSources() { return federatedSources; }

    /**
     * Container for the {@code federated_identities}, {@code federated_identities_ial2}, and
     * {@code federated_sources} claims. The {@code sources} and {@code identities} maps are keyed
     * by IDP short name (e.g. {@code "era"}, {@code "login.gov"}). {@code identities} is null for
     * the {@code federated_sources} claim.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class FederatedIdentities {

        /** Identity RAS treats as the user's default (the higher-assurance one at IAL2). */
        @JsonProperty("default_identity")
        private String defaultIdentity;

        /** Identity used in the current authentication. */
        @JsonProperty("authenticated_identity")
        private String authenticatedIdentity;

        /** IDP short name -> source record (immutable username, ial, immutable sub). */
        @JsonProperty("sources")
        private Map<String, FederatedSource> sources;

        /** IDP short name -> per-IDP identity detail. Null for the {@code federated_sources} claim. */
        @JsonProperty("identities")
        private Map<String, FederatedIdentityDetail> identities;

        public String getDefaultIdentity() { return defaultIdentity; }
        public String getAuthenticatedIdentity() { return authenticatedIdentity; }
        public Map<String, FederatedSource> getSources() { return sources; }
        public Map<String, FederatedIdentityDetail> getIdentities() { return identities; }
    }

    /** A single entry under {@code sources}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class FederatedSource {

        /** Immutable username for this linked identity; usable for cross-IDP correlation. */
        @JsonProperty("identity_username")
        private String identityUsername;

        /** Identity Assurance Level of this linked identity (typically 1 or 2). */
        @JsonProperty("ial")
        private Integer ial;

        /** Opaque immutable subject id for this linked identity. */
        @JsonProperty("identity_sub")
        private String identitySub;

        public String getIdentityUsername() { return identityUsername; }
        public Integer getIal() { return ial; }
        public String getIdentitySub() { return identitySub; }
    }

    /**
     * A single entry under {@code identities}. Note the field names here are RAS's compact
     * spellings ({@code firstname}/{@code lastname}/{@code userid}), distinct from the top-level
     * profile claims ({@code first_name}/{@code last_name}). {@code firstname}/{@code lastname}
     * may be absent for identities not proofed at IAL2.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class FederatedIdentityDetail {

        @JsonProperty("mail")
        private String mail;

        @JsonProperty("userid")
        private String userId;

        @JsonProperty("firstname")
        private String firstName;

        @JsonProperty("lastname")
        private String lastName;

        public String getMail() { return mail; }
        public String getUserId() { return userId; }
        public String getFirstName() { return firstName; }
        public String getLastName() { return lastName; }
    }
}
