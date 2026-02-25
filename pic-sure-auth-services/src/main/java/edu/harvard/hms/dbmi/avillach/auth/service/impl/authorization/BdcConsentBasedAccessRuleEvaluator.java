package edu.harvard.hms.dbmi.avillach.auth.service.impl.authorization;

import edu.harvard.hms.dbmi.avillach.auth.entity.AccessRule;
import edu.harvard.hms.dbmi.avillach.auth.entity.UserConsents;
import edu.harvard.hms.dbmi.avillach.hpds.data.query.v3.AuthorizationFilter;
import edu.harvard.hms.dbmi.avillach.hpds.data.query.v3.PhenotypicFilter;
import edu.harvard.hms.dbmi.avillach.hpds.data.query.v3.Query;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class BdcConsentBasedAccessRuleEvaluator implements ConsentBasedAccessRuleEvaluator {

    private final Logger log = LoggerFactory.getLogger(BdcConsentBasedAccessRuleEvaluator.class);

    private static final String GENOMIC_AUTHORIZATION_FILTER = "\\_topmed_consents\\";
    private static final String HARMONIZED_AUTHORIZATION_FILTER = "\\_harmonized_consent\\";

    @Override
    public boolean evaluateAccessRule(Query query, AccessRule accessRule, UserConsents consents) {
        Set<String> userStudies = consents.getConsents().values().stream().flatMap(Collection::stream)
                .map(consent -> consent.split("\\.")[0]).collect(Collectors.toSet());

        for (PhenotypicFilter phenotypicFilter : query.allFilters()) {
            if (!isConceptPathAuthorized(phenotypicFilter.conceptPath(), consents, userStudies))
                return false;
        }

        for (String conceptPath : query.select()) {
            if (!isConceptPathAuthorized(conceptPath, consents, userStudies))
                return false;
        }

        if (!query.genomicFilters().isEmpty()) {
            if (!consents.getConsents().containsKey(GENOMIC_AUTHORIZATION_FILTER)) {
                log.info("Genomic filters must contain the following authorization concepts: " + String.join(", ", GENOMIC_AUTHORIZATION_FILTER));
                return false;
            }
        }

        return true;
    }

    private boolean isConceptPathAuthorized(String conceptPath, UserConsents consents, Set<String> userStudies) {
        // the 0th index of the array is empty because consents start with \\
        String[] split = conceptPath.split("\\\\");
        String filterConsent = split.length > 1 ? split[1] : split[0];

        if (filterConsent.equals("DCC Harmonized data set")) {
            if (!consents.getConsents().containsKey(HARMONIZED_AUTHORIZATION_FILTER)) {
                log.info("User must have at least one consent in " + HARMONIZED_AUTHORIZATION_FILTER + " to use filter " + conceptPath);
                return false;
            }
        } else if (!userStudies.contains(filterConsent)) {
            log.info("User does not have study: " + filterConsent + " to access " + conceptPath);
            return false;
        }
        return true;
    }

    @Override
    public Query setAuthorizationFiltersForQuery(UserConsents userConsents, Query query) {
        List<AuthorizationFilter> authorizationFilter = userConsents.getConsents().entrySet().stream()
                .filter(entry -> {
                    if (entry.getKey().equals(GENOMIC_AUTHORIZATION_FILTER) && query.genomicFilters().isEmpty()) {
                        return false;
                    }
                    if (entry.getKey().equals(HARMONIZED_AUTHORIZATION_FILTER)) {
                        long harmonizedFilterCount = query.allFilters().stream().filter(filter -> filter.conceptPath().startsWith("\\DCC Harmonized data set\\")).count();
                        // leave these consents if there are any filters on harmonized concept paths
                        return harmonizedFilterCount > 0;
                    }
                    return true;
                })
                .map(entry -> new AuthorizationFilter(entry.getKey(), entry.getValue())).toList();

        return query.setAuthorizationFilters(authorizationFilter);
    }
}
