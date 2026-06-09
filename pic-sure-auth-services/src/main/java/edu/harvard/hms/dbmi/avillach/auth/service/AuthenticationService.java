package edu.harvard.hms.dbmi.avillach.auth.service;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public interface AuthenticationService {

    HashMap<String, String> authenticate(Map<String, String> authRequest, String requestHost) throws IOException;

    String getProvider();

    boolean isEnabled();

    /**
     * Providers that build their authorization redirect server-side — so state and nonce can be
     * generated here and verified at callback — return it from this method. Others inherit the
     * empty default and keep building the redirect in the client.
     */
    default Optional<String> getAuthorizeUrl(String requestHost) {
        return Optional.empty();
    }

}
