package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

    @Value("ras.uri")
    private String rasURI;

    @Autowired
    public RASPassPortService(RestClientUtil restClientUtil) {
        this.restClientUtil = restClientUtil;
    }

    @PostConstruct
    public void init() {
        // remove any trailing / from the rasURI.
        rasURI = rasURI.replaceAll("/$", "");
    }

    public Optional<JsonNode> validatePassport(String passport) {
        // send the passport to the https://stsstg.nih.gov/passport/validate?visa=<the encoded passport>
        MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
        queryParams.add("visa", passport);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(queryParams);

        JsonNode respJson;
        ResponseEntity<String> resp;
        try {
            resp = this.restClientUtil.retrievePostResponse("/passport/validate", request);
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
                logger.info("ga4gh_passport_v1: {}", ga4ghPassportV1);

                rasDbgapPermissions.addAll(ga4ghPassportV1.getRasDbgagPermissions());
            }
        });

        return rasDbgapPermissions;
    }

    public void setRasURI(String rasURI) {
        this.rasURI = rasURI;
    }
}
