package edu.harvard.hms.dbmi.avillach.auth.service.impl.authorization;

import edu.harvard.hms.dbmi.avillach.auth.model.fenceMapping.StudyMetaData;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasDbgapPermission;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;


public class BdcConsentsBuilder {

    private final Logger log = LoggerFactory.getLogger(BdcConsentsBuilder.class);

    public static final String CONSENTS_KEY = "\\_consent\\";
    public static final String HARMONIZED_CONSENTS_KEY = "\\_harmonized_consents\\";
    public static final String TOPMED_CONSENTS_KEY = "\\_topmed_consents\\";
    private final Map<String, StudyMetaData> fenceMappingByConsent;

    private final Set<RasDbgapPermission> dbgapRoleNames;

    public BdcConsentsBuilder(Map<String, StudyMetaData> fenceMappingByConsent, Set<RasDbgapPermission> dbgapRoleNames) {
        this.fenceMappingByConsent = fenceMappingByConsent;
        this.dbgapRoleNames = dbgapRoleNames;
    }

    public Map<String, Set<String>> createConsents() {
        Set<String> userConsentStrings = dbgapRoleNames.stream()
                .map(permission -> permission.getPhsId() + "." + permission.getConsentGroup())
                .collect(Collectors.toSet());

        Map<String, Set<String>> result = new HashMap<>();

        userConsentStrings.forEach(consent -> {
            StudyMetaData studyMetaData = fenceMappingByConsent.get(consent);
            if (studyMetaData == null) {
                log.info(consent + " not found in fence mapping");
                return;
            }
            result.computeIfAbsent(CONSENTS_KEY, _ -> new HashSet<>()).add(consent);

            if (studyMetaData.getIsHarmonized()) {
                Set<String> harmonizedConsents = result.getOrDefault(HARMONIZED_CONSENTS_KEY, new HashSet<>());
                harmonizedConsents.add(consent);
                result.put(HARMONIZED_CONSENTS_KEY, harmonizedConsents);
            }

            if (studyMetaData.getDataType() != null && studyMetaData.getDataType().contains("G")) {
                Set<String> topmedConsents = result.getOrDefault(TOPMED_CONSENTS_KEY, new HashSet<>());
                topmedConsents.add(consent);
                result.put(TOPMED_CONSENTS_KEY, topmedConsents);
            }
        });

        return result;
    }
}
