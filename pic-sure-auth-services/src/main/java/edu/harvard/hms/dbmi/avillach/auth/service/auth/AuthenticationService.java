package edu.harvard.hms.dbmi.avillach.auth.service.auth;

import com.fasterxml.jackson.databind.JsonNode;
import edu.harvard.dbmi.avillach.util.HttpClientUtil;
import edu.harvard.dbmi.avillach.util.exception.ApplicationException;
import edu.harvard.dbmi.avillach.util.exception.ProtocolException;
import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.RoleRepository;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.UserRepository;
import edu.harvard.hms.dbmi.avillach.auth.rest.UserService;
import edu.harvard.hms.dbmi.avillach.auth.service.MailService;
import edu.harvard.hms.dbmi.avillach.auth.service.OauthUserMatchingService;
import edu.harvard.hms.dbmi.avillach.auth.service.TOSService;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthUtils;
import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;


import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.*;

/**
 * This class provides authentication functionality. This implements an authenticationService interface
 * in the future to support different modes of authentication.
 *
 * <h3>Thoughts of design</h3>
 * The main purpose of this class is returns a token that includes information of the roles of users.
 */
public class AuthenticationService {
    private Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    @Inject
    OauthUserMatchingService matchingService;

    @Inject
    UserRepository userRepository;

    @Inject
    RoleRepository roleRepo;

    @Inject
    TOSService tosService;

    @Inject
    MailService mailService;

    @Inject
    UserService userService;

    @Inject
    AuthUtils authUtil;

    public Response getToken(Map<String, String> authRequest){
        String accessToken = authRequest.get("access_token");
        String redirectURI = authRequest.get("redirectURI");

        if (accessToken == null || redirectURI == null || accessToken.isEmpty() || redirectURI.isEmpty())
            throw new ProtocolException("Missing accessToken or redirectURI in request body.");

        JsonNode userInfo = retrieveUserInfo(accessToken);
        JsonNode userIdNode = userInfo.get("user_id");
        if (userIdNode == null){
            logger.error("getToken() cannot find user_id by retrieveUserInfo(), return json response: " + userInfo.toString());
            throw new ApplicationException("cannot get sufficient user information. Please contact admin.");
        }
        String userId = userIdNode.asText();

        logger.info("Successfully retrieved userId, " + userId +
                ", from the provided code and redirectURI");

        String connectionId;
        try {
            connectionId = userInfo.get("identities").get(0).get("connection").asText();
        } catch (Exception e){
            logger.error("getToken() cannot find connection_id by retrieveUserInfo(), return json response: " + userInfo.toString());
            throw new ApplicationException("cannot get sufficient user information. Please contact admin.");
        }

        User user = userRepository.findBySubjectAndConnection(userId, connectionId);
        if  (user == null){
            //Try to match
            user = matchingService.matchTokenToUser(userInfo);
            if (user == null){
                if (JAXRSConfiguration.deniedEmailEnabled.startsWith("true")) {
                    mailService.sendDeniedAccessEmail(userInfo);
                }
                throw new NotAuthorizedException("No user matching user_id " + userId + " present in database");
            }
        }

        HashMap<String, Object> claims = new HashMap<>();
        claims.put("sub", userId);
        claims.put("name", user.getName());
        claims.put("email", user.getEmail());
        HashMap<String, String> responseMap = authUtil.getUserProfileResponse(claims);
        
		logger.info("LOGIN SUCCESS ___ " + user.getEmail() + ":" + user.getUuid().toString() + " ___ Authorization will expire at  ___ " + responseMap.get("expirationDate") + "___");
		
        return PICSUREResponse.success(responseMap);
    }

    private JsonNode retrieveUserInfo(String accessToken){
        String auth0UserInfoURI = JAXRSConfiguration.auth0host + "/userinfo";
        List<Header> headers = new ArrayList<>();
        headers.add(new BasicHeader("Content-Type", MediaType.APPLICATION_JSON));
        headers.add(new BasicHeader("Authorization", "Bearer " + accessToken));
        return HttpClientUtil.simpleGet(auth0UserInfoURI,
                JAXRSConfiguration.client,
                JAXRSConfiguration.objectMapper,
                headers.toArray(new Header[headers.size()]));
    }

    private Map<String, Object> generateClaims(JsonNode userInfo, String... fields){
        Map<String, Object> claims = new HashMap<>();

        for (String field : fields) {
            JsonNode node = userInfo.get(field);
            if (node != null)
                claims.put(field, node.asText());
        }

        return claims;
    }
}
