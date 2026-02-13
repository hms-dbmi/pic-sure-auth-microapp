package edu.harvard.hms.dbmi.avillach.auth.service.impl.authorization;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.hms.dbmi.avillach.auth.entity.UserConsents;
import edu.harvard.hms.dbmi.avillach.hpds.data.query.ResultType;
import edu.harvard.hms.dbmi.avillach.hpds.data.query.v3.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class ConsentBasedAccessRuleEvaluatorTest {


    private ConsentBasedAccessRuleEvaluator consentBasedAccessRuleEvaluator;

    @BeforeEach
    public void setup() {
        consentBasedAccessRuleEvaluator = new ConsentBasedAccessRuleEvaluator();
    }

    @Test
    public void evaluateAccessRule_validAuthorizationFilters_accept() throws JsonProcessingException {
        UserConsents userConsents = new UserConsents().setConsents(Map.of("\\_consents\\", Set.of("phs123.c1", "phs456.c2")));
        Query query = new Query(
                List.of(),
                List.of(),
                new PhenotypicSubquery(
                        null,
                        List.of(
                                new PhenotypicFilter(
                                        PhenotypicFilterType.FILTER, "\\phs123\\data\\age\\", null, 30.0, 40.0, null
                                ),
                                new PhenotypicFilter(
                                        PhenotypicFilterType.FILTER, "\\phs456\\data\\age\\", null, 30.0, 40.0, null
                                ),
                                new PhenotypicFilter(
                                        PhenotypicFilterType.FILTER, "\\phs123\\data\\sex\\", Set.of("male", "female"), null, null, null
                                )
                        ),
                        Operator.AND
                ), null, ResultType.COUNT, null, null
        );

        boolean result = consentBasedAccessRuleEvaluator.evaluateAccessRule(query, null, userConsents);
        assertTrue(result);
    }

    @Test
    public void evaluateAccessRule_authorizationFiltersWrongConsent_reject() throws JsonProcessingException {
        UserConsents userConsents = new UserConsents().setConsents(Map.of("\\_consents\\", Set.of("phs123.c1", "phs456.c2")));
        Query query = new Query(
                List.of(),
                List.of(),
                new PhenotypicSubquery(
                        null,
                        List.of(
                                new PhenotypicFilter(
                                        PhenotypicFilterType.FILTER, "\\phs123\\data\\age\\", null, 30.0, 40.0, null
                                ),
                                new PhenotypicFilter(
                                        PhenotypicFilterType.FILTER, "\\phs456\\data\\age\\", null, 30.0, 40.0, null
                                ),
                                new PhenotypicFilter(
                                        PhenotypicFilterType.FILTER, "\\phs789\\data\\sex\\", Set.of("male", "female"), null, null, null
                                )
                        ),
                        Operator.AND
                ), null, ResultType.COUNT, null, null
        );

        boolean result = consentBasedAccessRuleEvaluator.evaluateAccessRule(query, null, userConsents);
        assertFalse(result);
    }


    @Test
    public void evaluateAccessRule_userNoConsentsWithAuthorizationFilter_reject() throws JsonProcessingException {
        UserConsents userConsents = new UserConsents().setConsents(Map.of());
        Query query = new Query(
                List.of(),
                List.of(),
                new PhenotypicSubquery(
                        null,
                        List.of(
                                new PhenotypicFilter(
                                        PhenotypicFilterType.FILTER, "\\phs123\\data\\age\\", null, 30.0, 40.0, null
                                ),
                                new PhenotypicFilter(
                                        PhenotypicFilterType.FILTER, "\\phs456\\data\\age\\", null, 30.0, 40.0, null
                                ),
                                new PhenotypicFilter(
                                        PhenotypicFilterType.FILTER, "\\phs123\\data\\sex\\", Set.of("male", "female"), null, null, null
                                )
                        ),
                        Operator.AND
                ), null, ResultType.COUNT, null, null
        );

        boolean result = consentBasedAccessRuleEvaluator.evaluateAccessRule(query, null, userConsents);
        assertFalse(result);
    }

    @Test
    public void evaluateAccessRule_genomicFiltersTopmedConsents_accept() throws JsonProcessingException {
        var expectedAuthFilters = List.of(
                new AuthorizationFilter("\\_consents\\", Set.of("phs123.c1", "phs456.c2")),
                new AuthorizationFilter("\\_topmed_consents\\", Set.of("phs123.c1", "phs456.c2"))
        );

        Map<String, Set<String>> consents = Map.of(
                "\\_consents\\", Set.of("phs123.c1", "phs456.c2"),
                "\\_topmed_consents\\", Set.of("phs123.c1", "phs456.c2")
        );
        UserConsents userConsents = new UserConsents().setConsents(consents);
        Query query = new Query(
                List.of(),
                List.of(),
                new PhenotypicSubquery(
                        null,
                        List.of(
                                new PhenotypicFilter(
                                        PhenotypicFilterType.FILTER, "\\phs123\\data\\age\\", null, 30.0, 40.0, null
                                ),
                                new PhenotypicFilter(
                                        PhenotypicFilterType.FILTER, "\\phs456\\data\\age\\", null, 30.0, 40.0, null
                                ),
                                new PhenotypicFilter(
                                        PhenotypicFilterType.FILTER, "\\phs123\\data\\sex\\", Set.of("male", "female"), null, null, null
                                )
                        ),
                        Operator.AND
                ),
                List.of(new GenomicFilter("Gene_with_variant", List.of("CDH8"), null, null)),
                ResultType.COUNT, null, null
        );

        boolean result = consentBasedAccessRuleEvaluator.evaluateAccessRule(query, null, userConsents);
        assertTrue(result);
    }


    @Test
    public void evaluateAccessRule_genomicFiltersNoTopmedConsents_reject() throws JsonProcessingException {
        UserConsents userConsents = new UserConsents().setConsents(Map.of("\\_consents\\", Set.of("phs123.c1", "phs456.c2")));
        Query query = new Query(
                List.of(),
                List.of(),
                new PhenotypicSubquery(
                        null,
                        List.of(
                                new PhenotypicFilter(
                                        PhenotypicFilterType.FILTER, "\\phs123\\data\\age\\", null, 30.0, 40.0, null
                                ),
                                new PhenotypicFilter(
                                        PhenotypicFilterType.FILTER, "\\phs456\\data\\age\\", null, 30.0, 40.0, null
                                ),
                                new PhenotypicFilter(
                                        PhenotypicFilterType.FILTER, "\\phs123\\data\\sex\\", Set.of("male", "female"), null, null, null
                                )
                        ),
                        Operator.AND
                ),
                List.of(new GenomicFilter("Gene_with_variant", List.of("CDH8"), null, null)),
                ResultType.COUNT, null, null
        );

        boolean result = consentBasedAccessRuleEvaluator.evaluateAccessRule(query, null, userConsents);
        assertFalse(result);
    }
}