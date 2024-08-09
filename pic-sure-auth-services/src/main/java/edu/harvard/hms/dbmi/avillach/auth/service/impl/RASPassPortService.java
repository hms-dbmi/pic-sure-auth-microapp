package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.enums.PassportValidationResponse;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.Ga4ghPassportV1;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.Passport;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasDbgapPermission;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import jakarta.annotation.PostConstruct;
import org.apache.commons.lang3.StringUtils;
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
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class RASPassPortService {

    private final Logger logger = LoggerFactory.getLogger(RASPassPortService.class);
    private final RestClientUtil restClientUtil;
    private final UserService userService;

    private String rasURI;

    @Autowired
    public RASPassPortService(RestClientUtil restClientUtil,
                              UserService userService,
                              @Value("${ras.idp.uri}") String rasURI) {
        this.restClientUtil = restClientUtil;
        this.userService = userService;
        this.rasURI = rasURI;
    }

    @PostConstruct
    public void init() {
        // remove any trailing / from the rasURI if it was included.
        rasURI = rasURI.replaceAll("/$", "");
        logger.info("RASPassPortService initialized with rasURI: {}", rasURI);
    }

    /**
     * We will run this nearly immediately after startup. We don't know how long it has been since the last auth micro app
     * ran its validate.
     */
    @Scheduled(initialDelay = 1000, fixedDelay = 3000000)
    public void validateAllUserPassports() {
        Set<User> allUsersWithAPassport = this.userService.getAllUsersWithAPassport();
        allUsersWithAPassport.parallelStream().forEach(user -> {
            if (StringUtils.isBlank(user.getPassport())) {
                logger.error("User {} has no passport.", user.getSubject());
                return;
            }

            String encodedPassport = user.getPassport();
            Optional<Passport> passportOptional = JWTUtil.parsePassportJWTV11(encodedPassport);
            if (passportOptional.isEmpty()) {
                logger.error("Failed to decode passport for user: {}", user.getEmail());
                user.setPassport(null);
                userService.save(user);
                userService.logoutUser(user);
                return;
            }

            List<String> ga4ghPassportV1 = passportOptional.get().getGa4ghPassportV1();
            for (String visa : ga4ghPassportV1) {
                Optional<Ga4ghPassportV1> parsedVisa = JWTUtil.parseGa4ghPassportV1(visa);
                if (parsedVisa.isEmpty()) {
                    logger.error("validatePassport() ga4ghPassportV1 is empty");
                    return;
                }

                if (parsedVisa.get().getExp() < System.currentTimeMillis() / 1000) {
                    handleFailedValidationResponse(PassportValidationResponse.VISA_EXPIRED.getValue(), user);
                } else {
                    Optional<String> response = validateVisa(visa);
                    if (response.isPresent()) {
                        boolean successfullyUpdated = handlePassportValidationResponse(response.get(), user);
                        if (!successfullyUpdated) {
                            logger.info("User {}'s passport is no longer valid. User logged out.", user.getSubject());
                            break;
                        }
                    }
                }
            }
        });

    }

    private boolean handlePassportValidationResponse(String response, User user) {
        PassportValidationResponse passportValidationResponse = PassportValidationResponse.fromValue(response);
        if (passportValidationResponse == null) {
            logger.error("handlePassportValidationResponse() passportValidationResponse is null");
            return false;
        }

        return switch (passportValidationResponse) {
            case VALID -> handleValidValidationResponse(response, user);
            case PERMISSION_UPDATE, INVALID, MISSING, INVALID_PASSPORT, VISA_EXPIRED, TXN_ERROR, EXPIRATION_ERROR, VALIDATION_ERROR,
                 EXPIRED_POLLING -> handleFailedValidationResponse(response, user);
        };
    }

    /**
     * If a passport is anything but VALID the user will be logged out and their passport be cleared.
     *
     * @param validateResponse The response from the passport validation
     * @param user             The user to log out
     * @return true if the user was successfully updated
     */
    private boolean handleFailedValidationResponse(String validateResponse, User user) {
        user.setPassport(null);
        this.userService.save(user);
        this.userService.logoutUser(user);
        this.logger.info("handleFailedValidationResponse - {} - USER LOGGED OUT - {}", validateResponse, user.getSubject());
        return false;
    }

    private boolean handleValidValidationResponse(String validateResponse, User user) {
        this.logger.info("handleValidValidationResponse: PASSPORT VALIDATE RESPONSE __ {} __ FOR USER: {}", validateResponse, user.getSubject());
        return true;
    }

    public Optional<String> validateVisa(String visa) {
        if (StringUtils.isBlank(visa)) {
            logger.error("validatePassport() passport is null");
            return Optional.empty();
        }

        MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
        queryParams.add("visa", visa);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(queryParams, null);

        String responseVal = PassportValidationResponse.VISA_EXPIRED.getValue();
        ResponseEntity<String> resp;
        try {
            resp = this.restClientUtil.retrievePostResponse(this.rasURI + "/passport/validate", request);
            responseVal = resp.getBody();
        } catch (Exception e) {
            logger.error("validatePassport() Passport validation failed: {}", e.getMessage());
        }

        return Optional.ofNullable(responseVal);
    }

    public Set<RasDbgapPermission> ga4gpPassportToRasDbgapPermissions(List<String> ga4ghPassports) {
        if (ga4ghPassports == null) {
            return null;
        }

        HashSet<RasDbgapPermission> rasDbgapPermissions = new HashSet<>();
        ga4ghPassports.forEach(ga4ghPassport -> {
            Optional<Ga4ghPassportV1> parsedGa4ghPassportV1 = JWTUtil.parseGa4ghPassportV1(ga4ghPassport);
            if (parsedGa4ghPassportV1.isPresent()) {
                Ga4ghPassportV1 ga4ghPassportV1 = parsedGa4ghPassportV1.get();
                logger.info("ga4gh_passport_v1: {}", ga4ghPassportV1);

                rasDbgapPermissions.addAll(ga4ghPassportV1.getRasDbgagPermissions());
            }
        });

        return rasDbgapPermissions;
    }

    public void setRasURI(String rasURI) {
        this.rasURI = rasURI;
    }

    public Optional<Passport> extractPassport(JsonNode introspectResponse) {
        if (introspectResponse == null) {
            logger.error("extractPassport() introspectResponse is null");
            return Optional.empty();
        }

        if (!introspectResponse.has("passport_jwt_v11")) {
            logger.error("extractPassport() introspectResponse does not have passport_jwt_v11");
            return Optional.empty();
        }

        return JWTUtil.parsePassportJWTV11(introspectResponse.get("passport_jwt_v11").toString());
    }
}
