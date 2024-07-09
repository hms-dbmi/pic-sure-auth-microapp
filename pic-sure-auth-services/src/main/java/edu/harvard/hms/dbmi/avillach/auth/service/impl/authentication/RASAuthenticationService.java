package edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mysql.cj.xdevapi.JsonArray;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.service.AuthenticationService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.AccessRuleService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.UserService;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class RASAuthenticationService extends OktaAuthenticationService implements AuthenticationService {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final UserService userService;
    private final String connectionId;
    private final boolean isEnabled;
    private final AccessRuleService accessRuleService;

    /**
     * Constructor for the RASAuthenticationService
     * @param userService The user service
     * @param idp_provider_uri The IDP provider URI
     * @param connectionId The connection ID
     * @param clientId The client ID
     * @param clientSecret The client secret
     */
    @Autowired
    public RASAuthenticationService(UserService userService,
                                    AccessRuleService accessRuleService,
                                    RestClientUtil restClientUtil,
                                    @Value("${ras.okta.idp.provider.is.enabled}") boolean isEnabled,
                                    @Value("${ras.okta.idp.provider.uri}") String idp_provider_uri,
                                    @Value("${ras.okta.connection.id}") String connectionId,
                                    @Value("${ras.okta.client.id}") String clientId,
                                    @Value("${ras.okta.client.secret}") String clientSecret) {
        super(idp_provider_uri, clientId, clientSecret, restClientUtil);

        this.userService = userService;
        this.connectionId = connectionId;
        this.isEnabled = isEnabled;

        logger.info("RASAuthenticationService is enabled: {}", isEnabled);
        logger.info("RASAuthenticationService initialized");
        logger.info("idp_provider_uri: {}", idp_provider_uri);
        logger.info("connectionId: {}", connectionId);

        this.accessRuleService = accessRuleService;
    }

    /**
     * Authenticate the user using the code provided by the IDP. This code is exchanged for an access token.
     * The access token is then used to introspect the user. The user is then loaded from the database.
     * If the user does not exist, we will reject their login attempt.
     *
     * @param host       The host of the request
     * @param authRequest The request body
     * @return The response from the authentication attempt
     */
    @Override
    public HashMap<String, String> authenticate(Map<String, String> authRequest, String host) {
        logger.info("OKTA LOGIN ATTEMPT ___ {} ___", authRequest.get("code"));

        String code = authRequest.get("code");
        if (StringUtils.isNotBlank(code)) {
            JsonNode userToken = super.handleCodeTokenExchange(host, code);
            JsonNode introspectResponse = super.introspectToken(userToken);
            User user = initializeUser(introspectResponse);
            if (user == null) {
                return null;
            }

            HashMap<String, String> responseMap = createUserClaims(user);
            logger.info("LOGIN SUCCESS ___ {}:{} ___ Authorization will expire at  ___ {}___", user.getEmail(), user.getUuid().toString(), responseMap.get("expirationDate"));

            return responseMap;
        }

        logger.info("LOGIN FAILED ___ USER NOT AUTHENTICATED ___");
        return null;
    }

    private User initializeUser(JsonNode introspectResponse) {
        if (introspectResponse == null) {
            logger.info("FAILED TO INTROSPECT TOKEN ___ ");
            return null;
        }

        boolean isActive = introspectResponse.get("active").asBoolean();
        if (!isActive) {
            logger.info("LOGIN FAILED ___ USER IS NOT ACTIVE ___ ");
            return null;
        }

        User user = userService.loadUser(introspectResponse, this.connectionId, "ras");
        if (user == null) {
            return null;
        }

        user.setGeneralMetadata(generateUserMetadata(introspectResponse, user).toString());
        userService.save(user);
        logger.info("USER METADATA SUCCESSFULLY ADDED ___ USER DATA: {}", user.getGeneralMetadata());

        clearCache(user);
        return user;
    }

    /**
     * Create user claims to return to the client
     *
     * @param user The user
     * @return The user claims as a HashMap
     */
    private HashMap<String, String> createUserClaims(User user) {
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("name", user.getName());
        claims.put("email", user.getEmail());
        claims.put("sub", user.getSubject());
        return userService.getUserProfileResponse(claims);
    }

    private void clearCache(User user) {
        userService.evictFromCache(user.getEmail());
        accessRuleService.evictFromCache(user.getEmail());
    }

    /**
     * Generate the user metadata that will be stored in the database. This metadata is used to determine the user's
     * role and other information.
     *
     * @param introspectResponse The response from the introspect endpoint
     * @param user               The user
     * @return The user metadata as an ObjectNode
     */
    protected ObjectNode generateUserMetadata(JsonNode introspectResponse, User user) {
        // JsonNode is immutable, so we need to convert it to an ObjectNode
        ObjectNode objectNode = new ObjectMapper().createObjectNode();

        objectNode.put("role", "user");
        objectNode.put("sub", introspectResponse.get("sub").asText());
        objectNode.put("user_id", user.getUuid().toString());
        objectNode.put("username", user.getEmail());
        objectNode.put("email", user.getEmail());

        return objectNode;
    }


    /*
    TODO: Implement functionality to parse a ras passport
     */
    protected Set<String> ga4gpPassportToStudies(JsonNode introspectResponse) throws JsonProcessingException {
        if (introspectResponse == null) {
            return null;
        }

        // get ga4gh passport token
        JsonNode ga4ghPassports = introspectResponse.get("ga4gh_passport_v1");
//        logger.info(ga4ghPassports.toPrettyString());

        // extract the payload
        String[] passports = ga4ghPassports.toString().split("\\.");
        String base64EncodedPayload = passports[1];
        Base64.Decoder decoder = Base64.getDecoder();
        String payload = new String(decoder.decode(base64EncodedPayload));
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = mapper.readTree(payload);

        logger.info(jsonNode.toPrettyString());

        return new HashSet<>();
    }

    @Override
    public String getProvider() {
        return "ras";
    }

    @Override
    public boolean isEnabled() {
        return this.isEnabled;
    }

}