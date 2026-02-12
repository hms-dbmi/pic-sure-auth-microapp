package edu.harvard.hms.dbmi.avillach.auth.service.impl.authorization;

import edu.harvard.hms.dbmi.avillach.auth.model.fenceMapping.StudyMetaData;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasDbgapPermission;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class BdcConsentsBuilder {

    public static final String CONSENTS_KEY = "_consents";
    public static final String HARMONIZED_CONSENTS_KEY = "_harmonized_consents";
    public static final String TOPMED_CONSENTS_KEY = "_topmed_consents";
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
            result.computeIfAbsent(CONSENTS_KEY, _ -> new HashSet<>()).add(consent);

            StudyMetaData studyMetaData = fenceMappingByConsent.get(consent);
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
