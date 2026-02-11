package edu.harvard.hms.dbmi.avillach.auth.service.impl.authorization;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.hms.dbmi.avillach.auth.entity.AccessRule;
import edu.harvard.hms.dbmi.avillach.auth.entity.UserConsents;
import edu.harvard.hms.dbmi.avillach.hpds.data.query.v3.AuthorizationFilter;
import edu.harvard.hms.dbmi.avillach.hpds.data.query.v3.PhenotypicFilter;
import edu.harvard.hms.dbmi.avillach.hpds.data.query.v3.Query;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class ConsentBasedAccessRuleEvaluator {

    private final Logger log = LoggerFactory.getLogger(ConsentBasedAccessRuleEvaluator.class);

    private final ObjectMapper objectMapper;

    private static final Set<String> REQUIRED_GENOMIC_AUTHORIZATION_FILTERS = Set.of("\\_topmed_consents\\");
    private static final Set<String> REQUIRED_HARMONIZED_AUTHORIZATION_FILTERS = Set.of("\\_harmonized_consent\\");

    @Autowired
    public ConsentBasedAccessRuleEvaluator(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public boolean evaluateAccessRule(Object requestBody, AccessRule accessRule, UserConsents consents) {
        try {
            Query query = objectMapper.readValue((String) requestBody, Query.class);

            Set<String> userStudies = consents.getConsents().values().stream().flatMap(Collection::stream)
                    .map(consent -> consent.split("\\.")[0]).collect(Collectors.toSet());

            for (PhenotypicFilter phenotypicFilter : query.allFilters()) {
                // the 0th index of the array is empty because consents start with \\
                String filterConsent = phenotypicFilter.conceptPath().split("\\\\")[1];

                if (filterConsent.equals("DCC Harmonized data set")) {
                    if (consents.getConsents().keySet().containsAll(REQUIRED_HARMONIZED_AUTHORIZATION_FILTERS));
                }
                if (!userStudies.contains(filterConsent)) {
                    log.info("User does not have study: " + filterConsent);
                    return false;
                }
            }

            // todo: validate SELECT

            if (!query.genomicFilters().isEmpty()) {
                if (!consents.getConsents().keySet().containsAll(REQUIRED_GENOMIC_AUTHORIZATION_FILTERS)) {
                    log.info("Genomic filters must contain the following authorization concepts: " + String.join(", ", REQUIRED_GENOMIC_AUTHORIZATION_FILTERS));
                    return false;
                }
            }

        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return true;
    }
}
