package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.enums.PassportValidationResponse;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.Ga4ghPassportV1;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasDbgapPermission;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
public class RASPassPortService {

    private final Logger logger = LoggerFactory.getLogger(RASPassPortService.class);
    private final RestClientUtil restClientUtil;
    private final UserService userService;

    @Value("ras.uri")
    private String rasURI;

    @Autowired
    public RASPassPortService(RestClientUtil restClientUtil, UserService userService, SessionService sessionService) {
        this.restClientUtil = restClientUtil;
        this.userService = userService;
    }

    @PostConstruct
    public void init() {
        // remove any trailing / from the rasURI if it was included.
        rasURI = rasURI.replaceAll("/$", "");
    }

    /**
     * We will run this nearly immediately after startup. We don't know how long it has been since the last auth micro app
     * ran its validate.
     */
//    @Scheduled(initialDelay = 1000, fixedDelay = 3000000)
    public void validateAllUserPassports() {
        /*
            - Load all users who have passports - DONE
            - Loop over the users and validate their passport - DONE
            - Handle the response from the validatePassport call - In Progress
            - Potentially add a scheduled job table. This will allow us to avoid running this job too often. - Write Proposal so team can review
         */

        Set<User> allUsersWithAPassport = this.userService.getAllUsersWithAPassport();
        allUsersWithAPassport.parallelStream().forEach(user -> {
            String passport = user.getPassport();
            Optional<JsonNode> jsonNode = validatePassport(passport);
            if (jsonNode.isPresent()) {
                boolean successfullyUpdated = handlePassportValidationResponse(jsonNode.get(), user);
                if (successfullyUpdated) {
                    logger.info("Successfully updated user passport for user: {}", user.getEmail());
                }
            }
        });

    }

    private boolean handlePassportValidationResponse(JsonNode jsonNode, User user) {
        return switch (PassportValidationResponse.valueOf(jsonNode.get("status").asText())) {
            case VALID -> handleValidValidationResponse(jsonNode, user);
            case PERMISSION_UPDATE, INVALID, MISSING, INVALID_PASSPORT, VISA_EXPIRED, TXN_ERROR, EXPIRATION_ERROR, VALIDATION_ERROR,
                 EXPIRED_POLLING -> handleFailedValidationResponse(jsonNode, user);
        };
    }

    /**
     * If a passport is anything but VALID the user will be logged out and their passport be cleared.
     *
     * @param validateResponse
     * @param user
     * @return
     */
    private boolean handleFailedValidationResponse(JsonNode validateResponse, User user) {
        user.setPassport(null);
        this.userService.save(user);
        this.userService.logoutUser(user);
        this.logger.info("handleFailedValidationResponse: {}", validateResponse);
        this.logger.info("User logged out for user: {}", user.getSubject());
        return true;
    }

    private boolean handleValidValidationResponse(JsonNode validateResponse, User user) {
        this.logger.info("handleValidValidationResponse: {}", validateResponse);
        this.logger.info("User {}'s passport is still VALID.", user.getSubject());
        return false;
    }

    public Optional<JsonNode> validatePassport(String passport) {
        // send the passport to the https://stsstg.nih.gov/passport/validate?visa=<the encoded passport>
        MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
        queryParams.add("visa", passport);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(queryParams);

        JsonNode respJson;
        ResponseEntity<String> resp;
        try {
            resp = this.restClientUtil.retrievePostResponse(this.rasURI + "/passport/validate", request);
            respJson = new ObjectMapper().readTree(resp.getBody());
        } catch (Exception e) {
            logger.error("Failed to validate passport: {}", passport, e);
            return Optional.empty();
        }

        return Optional.ofNullable(respJson);
    }

    public Set<RasDbgapPermission> ga4gpPassportToRasDbgapPermissions(JsonNode introspectResponse) {
        if (introspectResponse == null) {
            return null;
        }

        HashSet<RasDbgapPermission> rasDbgapPermissions = new HashSet<>();
        JsonNode ga4ghPassports = introspectResponse.get("ga4gh_passport_v1");
        ga4ghPassports.forEach(ga4ghPassport -> {
            Optional<Ga4ghPassportV1> parsedGa4ghPassportV1 = JWTUtil.parseGa4ghPassportV1(ga4ghPassport.toString());
            if (parsedGa4ghPassportV1.isPresent()) {
                Ga4ghPassportV1 ga4ghPassportV1 = parsedGa4ghPassportV1.get();
                logger.debug("ga4gh_passport_v1: {}", ga4ghPassportV1);

                rasDbgapPermissions.addAll(ga4ghPassportV1.getRasDbgagPermissions());
            }
        });

        return rasDbgapPermissions;
    }

    public void setRasURI(String rasURI) {
        this.rasURI = rasURI;
    }
}
