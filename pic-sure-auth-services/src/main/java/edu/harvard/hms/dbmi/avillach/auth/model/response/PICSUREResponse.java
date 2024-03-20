package edu.harvard.hms.dbmi.avillach.auth.model.response;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import java.util.HashMap;
import java.util.Map;

public class PICSUREResponse {

    private static final MediaType DEFAULT_MEDIA_TYPE = MediaType.APPLICATION_JSON;
    private static final HttpStatus DEFAULT_RESPONSE_ERROR_CODE = HttpStatus.INTERNAL_SERVER_ERROR;

    public static ResponseEntity<?> success() {
        return new ResponseEntity<>(HttpStatus.OK);
    }

    public static ResponseEntity<?> success(Object content) {
        return new ResponseEntity<>(content, HttpStatus.OK);
    }

    public static ResponseEntity<?> success(String message, Object content) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", message);
        response.put("content", content);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    public static ResponseEntity<?> error(Object content) {
        return error(DEFAULT_RESPONSE_ERROR_CODE, content);
    }

    public static ResponseEntity<?> error(String message, Object content) {
        return error(DEFAULT_RESPONSE_ERROR_CODE, message, content);
    }

    public static ResponseEntity<?> error(HttpStatus status, Object content) {
        if (status == null) {
            status = DEFAULT_RESPONSE_ERROR_CODE;
        }
        return new ResponseEntity<>(content, status);
    }

    public static ResponseEntity<?> error(HttpStatus status, String message, Object content) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", message);
        response.put("content", content);
        return new ResponseEntity<>(response, status);
    }

    public static ResponseEntity<?> applicationError(Object content) {
        return error(DEFAULT_RESPONSE_ERROR_CODE, "Application error", content);
    }

    public static ResponseEntity<?> applicationError(String message, Object content) {
        return error(DEFAULT_RESPONSE_ERROR_CODE, message, content);
    }

    public static ResponseEntity<?> riError(Object content) {
        return error(DEFAULT_RESPONSE_ERROR_CODE, "RI error", content);
    }

    public static ResponseEntity<?> riError(String message, Object content) {
        return error(DEFAULT_RESPONSE_ERROR_CODE, message, content);
    }

    public static ResponseEntity<?> protocolError(Object content) {
        return error(HttpStatus.BAD_REQUEST, content);
    }

    public static ResponseEntity<?> protocolError(String message, Object content) {
        return error(HttpStatus.BAD_REQUEST, message, content);
    }

    public static ResponseEntity<?> unauthorizedError(Object content) {
        return error(HttpStatus.UNAUTHORIZED, "Unauthorized", content);
    }

    public static ResponseEntity<?> unauthorizedError(String message, Object content) {
        return error(HttpStatus.UNAUTHORIZED, message, content);
    }
}

