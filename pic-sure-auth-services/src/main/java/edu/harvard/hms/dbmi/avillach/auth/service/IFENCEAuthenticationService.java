package edu.harvard.hms.dbmi.avillach.auth.service;

import org.springframework.http.ResponseEntity;

import java.util.Map;

public interface IFENCEAuthenticationService {

    ResponseEntity<?> getFENCEProfile(String callback_url, Map<String, String> authRequest);

    ResponseEntity<?> getFENCEProfile(Map<String, String> authRequest);

}
