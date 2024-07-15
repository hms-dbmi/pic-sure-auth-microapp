package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.Ga4ghPassportV1;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasDbgapPermission;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
public class RASPassPortService {

    private final Logger logger = LoggerFactory.getLogger(RASPassPortService.class);

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

}
