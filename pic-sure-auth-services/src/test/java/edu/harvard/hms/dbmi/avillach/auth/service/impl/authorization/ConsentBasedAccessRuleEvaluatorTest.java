package edu.harvard.hms.dbmi.avillach.auth.service.impl.authorization;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.hms.dbmi.avillach.hpds.data.query.ResultType;
import edu.harvard.hms.dbmi.avillach.hpds.data.query.v3.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ConsentBasedAccessRuleEvaluatorTest {


    private ConsentBasedAccessRuleEvaluator consentBasedAccessRuleEvaluator;

    @BeforeEach
    public void setup() {
        consentBasedAccessRuleEvaluator = new ConsentBasedAccessRuleEvaluator(new ObjectMapper());
    }

    @Test
    public void evaluateAccessRule_validAuthorizationFilters_accept() throws JsonProcessingException {
        Query query = new Query(
                List.of(),
                List.of(new AuthorizationFilter("\\_consents\\", List.of("phs123.c1", "phs456.c2"))),
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
                                        PhenotypicFilterType.FILTER, "\\phs123\\data\\sex\\", List.of("male", "female"), null, null, null
                                )
                        ),
                        Operator.AND
                ), null, ResultType.COUNT, null, null
        );

        String json = new ObjectMapper().writeValueAsString(query);

        boolean result = consentBasedAccessRuleEvaluator.evaluateAccessRule(json, null, Set.of("phs123.c1", "phs456.c2"));
        assertTrue(result);
    }

    @Test
    public void evaluateAccessRule_authorizationFiltersWrongConsent_reject() throws JsonProcessingException {
        Query query = new Query(
                List.of(),
                List.of(new AuthorizationFilter("\\_consents\\", List.of("phs123.c1", "phs456.c1"))),
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
                                        PhenotypicFilterType.FILTER, "\\phs123\\data\\sex\\", List.of("male", "female"), null, null, null
                                )
                        ),
                        Operator.AND
                ), null, ResultType.COUNT, null, null
        );

        String json = new ObjectMapper().writeValueAsString(query);

        boolean result = consentBasedAccessRuleEvaluator.evaluateAccessRule(json, null, Set.of("phs123.c1", "phs456.c2"));
        assertFalse(result);
    }


    @Test
    public void evaluateAccessRule_userNoConsentsWithAuthorizationFilter_reject() throws JsonProcessingException {
        Query query = new Query(
                List.of(),
                List.of(new AuthorizationFilter("\\_consents\\", List.of("phs123.c1", "phs456.c1"))),
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
                                        PhenotypicFilterType.FILTER, "\\phs123\\data\\sex\\", List.of("male", "female"), null, null, null
                                )
                        ),
                        Operator.AND
                ), null, ResultType.COUNT, null, null
        );

        String json = new ObjectMapper().writeValueAsString(query);

        boolean result = consentBasedAccessRuleEvaluator.evaluateAccessRule(json, null, Set.of());
        assertFalse(result);
    }

    @Test
    public void evaluateAccessRule_userConsentsNoAuthorizationFilters_accept() throws JsonProcessingException {
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
                                        PhenotypicFilterType.FILTER, "\\phs123\\data\\sex\\", List.of("male", "female"), null, null, null
                                )
                        ),
                        Operator.AND
                ), null, ResultType.COUNT, null, null
        );

        String json = new ObjectMapper().writeValueAsString(query);

        boolean result = consentBasedAccessRuleEvaluator.evaluateAccessRule(json, null, Set.of("phs123.c1", "phs456.c2"));
        assertTrue(result);
    }

    @Test
    public void evaluateAccessRule_genomicFiltersTopmedConsents_accept() throws JsonProcessingException {
        Query query = new Query(
                List.of(),
                List.of(
                        new AuthorizationFilter("\\_consents\\", List.of("phs123.c1", "phs456.c2")),
                        new AuthorizationFilter("\\_topmed_consents\\", List.of("phs123.c1", "phs456.c2"))
                ),
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
                                        PhenotypicFilterType.FILTER, "\\phs123\\data\\sex\\", List.of("male", "female"), null, null, null
                                )
                        ),
                        Operator.AND
                ),
                List.of(new GenomicFilter("Gene_with_variant", List.of("CDH8"), null, null)),
                ResultType.COUNT, null, null
        );

        String json = new ObjectMapper().writeValueAsString(query);

        boolean result = consentBasedAccessRuleEvaluator.evaluateAccessRule(json, null, Set.of("phs123.c1", "phs456.c2"));
        assertTrue(result);
    }


    @Test
    public void evaluateAccessRule_genomicFiltersNoTopmedConsents_reject() throws JsonProcessingException {
        Query query = new Query(
                List.of(),
                List.of(
                        new AuthorizationFilter("\\_consents\\", List.of("phs123.c1", "phs456.c2"))
                ),
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
                                        PhenotypicFilterType.FILTER, "\\phs123\\data\\sex\\", List.of("male", "female"), null, null, null
                                )
                        ),
                        Operator.AND
                ),
                List.of(new GenomicFilter("Gene_with_variant", List.of("CDH8"), null, null)),
                ResultType.COUNT, null, null
        );

        String json = new ObjectMapper().writeValueAsString(query);

        boolean result = consentBasedAccessRuleEvaluator.evaluateAccessRule(json, null, Set.of("phs123.c1", "phs456.c2"));
        assertFalse(result);
    }
}