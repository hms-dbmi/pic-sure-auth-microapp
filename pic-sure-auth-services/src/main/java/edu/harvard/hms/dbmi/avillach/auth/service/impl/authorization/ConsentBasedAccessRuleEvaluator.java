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
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class ConsentBasedAccessRuleEvaluator {

    private final Logger log = LoggerFactory.getLogger(ConsentBasedAccessRuleEvaluator.class);

    private static final String REQUIRED_GENOMIC_AUTHORIZATION_FILTERS = "\\_topmed_consents\\";
    private static final String REQUIRED_HARMONIZED_AUTHORIZATION_FILTERS = "\\_harmonized_consent\\";

    public boolean evaluateAccessRule(Query query, AccessRule accessRule, UserConsents consents) {
        Set<String> userStudies = consents.getConsents().values().stream().flatMap(Collection::stream)
                .map(consent -> consent.split("\\.")[0]).collect(Collectors.toSet());

        for (PhenotypicFilter phenotypicFilter : query.allFilters()) {
            // the 0th index of the array is empty because consents start with \\
            String filterConsent = phenotypicFilter.conceptPath().split("\\\\")[1];

            if (filterConsent.equals("DCC Harmonized data set")) {
                if (!consents.getConsents().containsKey(REQUIRED_HARMONIZED_AUTHORIZATION_FILTERS)) {
                    return false;
                }
            }
            if (!userStudies.contains(filterConsent)) {
                log.info("User does not have study: " + filterConsent);
                return false;
            }
        }

        // todo: validate SELECT

        if (!query.genomicFilters().isEmpty()) {
            if (!consents.getConsents().containsKey(REQUIRED_GENOMIC_AUTHORIZATION_FILTERS)) {
                log.info("Genomic filters must contain the following authorization concepts: " + String.join(", ", REQUIRED_GENOMIC_AUTHORIZATION_FILTERS));
                return false;
            }
        }

        return true;
    }
}
