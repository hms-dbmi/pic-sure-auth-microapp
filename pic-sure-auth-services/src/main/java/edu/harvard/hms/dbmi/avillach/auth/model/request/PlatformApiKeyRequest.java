package edu.harvard.hms.dbmi.avillach.auth.model.request;

import java.time.Instant;

public record PlatformApiKeyRequest(String name, String email, Instant expiresAt) {
}
