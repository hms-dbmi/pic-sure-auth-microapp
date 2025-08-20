package edu.harvard.hms.dbmi.avillach.auth.service.impl.authorization;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.hms.dbmi.avillach.auth.entity.AccessRule;
import edu.harvard.hms.dbmi.avillach.hpds.data.query.v3.AuthorizationFilter;
import edu.harvard.hms.dbmi.avillach.hpds.data.query.v3.PhenotypicFilter;
import edu.harvard.hms.dbmi.avillach.hpds.data.query.v3.Query;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;

@Component
public class ConsentBasedAccessRuleEvaluator {

    private final Logger log = LoggerFactory.getLogger(ConsentBasedAccessRuleEvaluator.class);

    private final ObjectMapper objectMapper;

    private static final Set<String> REQUIRED_GENOMIC_AUTHORIZATION_FILTERS = Set.of("\\_topmed_consents\\");

    @Autowired
    public ConsentBasedAccessRuleEvaluator(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public boolean evaluateAccessRule(Object requestBody, AccessRule accessRule, Set<String> consents) {
        try {
            Query query = objectMapper.readValue((String) requestBody, Query.class);

            for (AuthorizationFilter authorizationFilter : query.authorizationFilters()) {
                for (String value : authorizationFilter.values()) {
                    if (!consents.contains(value)) {
                        log.info("User does not have consent: " + value);
                        return false;
                    }
                }
            }

            Set<String> userStudies = consents.stream().map(consent -> consent.split("\\.")[0]).collect(Collectors.toSet());
            for (PhenotypicFilter phenotypicFilter : query.allFilters()) {
                // the 0th index of the array is empty because consents start with \\
                String filterConsent = phenotypicFilter.conceptPath().split("\\\\")[1];
                if (!userStudies.contains(filterConsent)) {
                    log.info("User does not have study: " + filterConsent);
                    return false;
                }
            }

            if (!query.genomicFilters().isEmpty()) {
                Set<String> authorizationConceptPaths = query.authorizationFilters().stream().map(AuthorizationFilter::conceptPath).collect(Collectors.toSet());
                if (!authorizationConceptPaths.containsAll(REQUIRED_GENOMIC_AUTHORIZATION_FILTERS)) {
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
