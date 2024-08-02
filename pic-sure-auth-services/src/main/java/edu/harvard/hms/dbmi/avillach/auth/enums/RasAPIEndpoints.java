package edu.harvard.hms.dbmi.avillach.auth.enums;

public enum RasAPIEndpoints {

    // Initiate process to allow resource owner to permit client access
    AUTHORIZE("/auth/oauth/v2/authorize"),

    // Prompts resource owner to login before permitting client access
    AUTHORIZE_LOGIN("/auth/oauth/v2/authorize/login"),

    // Prompts resource owner to allow or deny client access
    AUTHORIZE_CONSENT("/auth/oauth/v2/authorize/consent"),

    // Processes the token issuance step
    TOKEN("/auth/oauth/v2/token"),

    // If presented with a valid access token, returns claims about the requested user.
    // This endpoint can be used to receive a passport as an embedded token.
    USERINFO("/openid/connect/v1.1/userinfo"),

    // Terminates the current Open ID active session
    SESSION_LOGOUT("/connect/session/logout"),

    // Used to publish the JWK set public keys used by clients to validate a JSON Web token (JWT).
    JWKS("/openid/connect/jwks.json"),

    // Used for access polling and to validate that a Passport Visa is still valid & unexpired
    PASSPORT_VALIDATE("/passport/validate"),

    // Used for managing consent, including revoking and extending consent
    SETTINGS_CONSENT("/settings/consent");

    private final String value;

    RasAPIEndpoints(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}