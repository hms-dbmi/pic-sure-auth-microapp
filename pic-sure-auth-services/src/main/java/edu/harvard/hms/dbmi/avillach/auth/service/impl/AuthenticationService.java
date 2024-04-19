package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import java.io.IOException;
import java.util.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.hms.dbmi.avillach.auth.entity.Connection;
import edu.harvard.hms.dbmi.avillach.auth.exceptions.NotAuthorizedException;
import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.repository.ConnectionRepository;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;

import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

/**
 * This class provides authentication functionality. This implements an authenticationService interface
 * in the future to support different modes of authentication.
 *
 * <h3>Thoughts of design</h3>
 * The main purpose of this class is returns a token that includes information of the roles of users.
 */

@Service
public class AuthenticationService {

    private final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    private final OauthUserMatchingService matchingService;

    private final UserRepository userRepository;

    private final BasicMailService basicMailService;

    private final UserService userService;
    private static final int AUTH_RETRY_LIMIT = 3;

    private final String deniedEmailEnabled;

    private final String auth0host;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ConnectionRepository connectionRepository;

    @Autowired
    public AuthenticationService(OauthUserMatchingService matchingService, UserRepository userRepository, BasicMailService basicMailService, UserService userService,
                                 @Value("${application.denied.email.enabled}") String deniedEmailEnabled, @Value("${application.auth0.host}") String auth0host, ConnectionRepository connectionRepository) {
        this.matchingService = matchingService;
        this.userRepository = userRepository;
        this.basicMailService = basicMailService;
        this.userService = userService;
        this.deniedEmailEnabled = deniedEmailEnabled;
        this.auth0host = auth0host;
        this.connectionRepository = connectionRepository;
    }

    public ResponseEntity<?> getToken(Map<String, String> authRequest) throws IOException {
        String accessToken = authRequest.get("access_token");
        String redirectURI = authRequest.get("redirectURI");

        if (accessToken == null || redirectURI == null || accessToken.isEmpty() || redirectURI.isEmpty()) {
            throw new IllegalArgumentException("Missing accessToken or redirectURI in request body.");
        }

        JsonNode userInfo = retrieveUserInfo(accessToken);
        JsonNode userIdNode = userInfo.get("user_id");
        if (userIdNode == null) {
            logger.error("getToken() cannot find user_id by retrieveUserInfo(), return json response: {}", userInfo.toString());
            throw new NotAuthorizedException("cannot get sufficient user information. Please contact admin.");
        }
        String userId = userIdNode.asText();

        logger.info("Successfully retrieved userId, {}, from the provided code and redirectURI", userId);

        String connectionId;
        try {
            connectionId = userInfo.get("identities").get(0).get("connection").asText();
        } catch (Exception e) {
            logger.error("getToken() cannot find connection_id by retrieveUserInfo(), return json response: {}", userInfo.toString());
            throw new NotAuthorizedException("cannot get sufficient user information. Please contact admin.");
        }

        Connection connection = connectionRepository.findById(connectionId).orElseThrow(() -> new NotAuthorizedException("No connection found for connection_id " + connectionId));
        //Do we have this user already?
        User user = userRepository.findBySubjectAndConnection(userId, connection);
        if (user == null) {
            //Try to match
            user = matchingService.matchTokenToUser(userInfo);
            if (user == null) {
                if (this.deniedEmailEnabled.startsWith("true")) {
                    try {
                        basicMailService.sendDeniedAccessEmail(userInfo);
                    } catch (jakarta.mail.MessagingException e) {
                        throw new RuntimeException(e);
                    }
                }
                throw new NotAuthorizedException("No user matching user_id " + userId + " present in database");
            }
        }

        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("sub", userId);
        claims.put("name", user.getName());
        claims.put("email", user.getEmail());
        HashMap<String, String> responseMap = userService.getUserProfileResponse(claims);

        logger.info("LOGIN SUCCESS ___ " + user.getEmail() + ":" + user.getUuid().toString() + " ___ Authorization will expire at  ___ " + responseMap.get("expirationDate") + "___");

        return PICSUREResponse.success(responseMap);
    }

    private JsonNode retrieveUserInfo(String accessToken) throws IOException {
        // TODO: Remove this after debugging
        logger.info("accessToken: {}", accessToken);
        logger.info("auth0host: {}", this.auth0host);
        String auth0UserInfoURI = this.auth0host + "/userinfo";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + accessToken);

        JsonNode auth0Response = null;
//        RequestConfig requestConfig = createRequestConfigWithCustomTimeout(); // TODO: How can we do this with the Spring rest client?

        for (int i = 1; i <= AUTH_RETRY_LIMIT && auth0Response == null; i++) {
            try {
                ResponseEntity<String> response = RestClientUtil.retrieveGetResponse(
                        auth0UserInfoURI,
                        headers
                );

                auth0Response = objectMapper.readTree(response.getBody());
            } catch (Exception e) {
                if (i < AUTH_RETRY_LIMIT) {
                    logger.warn("Failed to authenticate.  Retrying");
                } else {
                    logger.error("Failed to authenticate.  Giving up!");
                    throw e;
                }
            }
        }
        return auth0Response;
    }
// TODO : This method is not used. we need to investigate if it is needed or not
//    private RequestConfig createRequestConfigWithCustomTimeout() {
//        int timeoutMs = 2000; // 2 seconds, default is 3 seconds
//        return RequestConfig.custom()
//                .setConnectionRequestTimeout(timeoutMs)
//                .setConnectTimeout(timeoutMs)
//                .setSocketTimeout(timeoutMs)
//                .build();
//    }
}
