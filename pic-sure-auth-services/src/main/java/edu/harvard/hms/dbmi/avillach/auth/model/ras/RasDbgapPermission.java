package edu.harvard.hms.dbmi.avillach.auth.model.ras;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The RasDbgapPermission class is a model for the RAS dbGaP Permission object. An example of this object is:
 * This is not a real study, but an example of what the object looks like.
 * <pre>
 *     {
 *       "consent_name": "Unrestricted",
 *       "phs_id": "phs000123",
 *       "version": "v1",
 *       "participant_set": "p1",
 *       "consent_group": "c1",
 *       "role": "pi",
 *       "expiration": 1234567890
 *     }
 * </pre>
 */
public class RasDbgapPermission {

    @JsonProperty("consent_name")
    private String consentName;
    @JsonProperty("phs_id")
    private String phsId;
    private String version;
    @JsonProperty("participant_set")
    private String participantSet;
    @JsonProperty("consent_group")
    private String consentGroup;
    private String role;
    private long expiration;

    public String getConsentName() {
        return consentName;
    }

    public void setConsentName(String consentName) {
        this.consentName = consentName;
    }

    public String getPhsId() {
        return phsId;
    }

    public void setPhsId(String phsId) {
        this.phsId = phsId;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getParticipantSet() {
        return participantSet;
    }

    public void setParticipantSet(String participantSet) {
        this.participantSet = participantSet;
    }

    public String getConsentGroup() {
        return consentGroup;
    }

    public void setConsentGroup(String consentGroup) {
        this.consentGroup = consentGroup;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public long getExpiration() {
        return expiration;
    }

    public void setExpiration(long expiration) {
        this.expiration = expiration;
    }

    @Override
    public String toString() {
        return "RasDbgapPermission{" +
                "consentName='" + consentName + '\'' +
                ", phsId='" + phsId + '\'' +
                ", version='" + version + '\'' +
                ", participantSet='" + participantSet + '\'' +
                ", consentGroup='" + consentGroup + '\'' +
                ", role='" + role + '\'' +
                ", expiration=" + expiration +
                '}';
    }
}
