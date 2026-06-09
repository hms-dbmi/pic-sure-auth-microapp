package edu.harvard.hms.dbmi.avillach.auth.model.ras;

/** Result of the RAS authorization-code token exchange. refreshToken may be null. */
public record RasOidcTokens(String accessToken, String idToken, String refreshToken) {}
