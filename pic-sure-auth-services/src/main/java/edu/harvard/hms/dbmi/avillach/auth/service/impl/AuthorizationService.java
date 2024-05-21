package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import edu.harvard.hms.dbmi.avillach.auth.entity.AccessRule;
import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.rest.TokenController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

/**
 * This class handles authorization activities in the project. It decides
 * if a user can send a request to certain applications based on
 * what endpoint they are trying to hit and the content of the request body (in HTTP POST method).
 * <h3>Thoughts on design:</h3>
 * The core technology used here is jsonpath.
 * In the {@link TokenController#inspectToken(Map)} class, other registered applications
 * can hit the tokenIntrospection endpoint with a token they want PSAMA to introspect along
 * with the URL the token holder is trying to hit and what data this token holder is trying to send. After
 * checking if the token is valid or not, the authorization check in this class will start.
 * <br><br>
 * <p>
 * Whether users are allowed access or not depends on their privileges, which depends on
 * the accessRules underneath. AuthorizationService class will eventually use jsonpath to check if
 * certain places in the incoming JSON meet the requirement of the preset rules in accessRules to determine
 * if the token holder is authorized or not.
 * </p>
 */
@Service
public class AuthorizationService {

    private final Logger logger = LoggerFactory.getLogger(AuthorizationService.class);

    private AccessRuleService accessRuleService;

    public AuthorizationService() {
    }

    @Autowired
    public AuthorizationService(AccessRuleService accessRuleService) {
        this.accessRuleService = accessRuleService;
    }

    /**
     * Checking based on AccessRule in Privilege
     * <br><br>
     * Thoughts on design:
     * <br>
     * <br>
     * We have three layers here: role, privilege, accessRule.
     * <br>
     * A role might have multiple privileges, a privilege might have multiple accessRules.
     * <br>
     * Currently, we retrieve all accessRules together. Between AccessRules, they should be OR relationship, which means
     * roles and privileges are OR relationship, pass one, and you are good.
     * <br>
     * <br>
     * Inside each accessRule, there are  subAccessRules and Gates.
     * <br>
     * Only if all gates are applied will the accessRule be checked.
     * <br>
     * The accessRule and subAccessRules are an AND relationship.
     *
     * @param application
     * @param requestBody
     * @return
     * @see Privilege
     * @see AccessRule
     */
    public boolean isAuthorized(Application application, Object requestBody, User user) {
        String applicationName = application.getName();
        //in some cases, we don't go through the evaluation
        if (requestBody == null) {
            logger.info("ACCESS_LOG ___ " + user.getUuid().toString() + "," + user.getEmail() + "," + user.getName() +
                    " ___ has been granted access to application ___ " + applicationName + " ___ NO REQUEST BODY FORWARDED BY APPLICATION");
            return true;
        }

        // start to process the jsonpath checking

        String formattedQuery = null;
        try {
            formattedQuery = (String) ((Map)requestBody).get("formattedQuery");

            if(formattedQuery == null) {
                //fallback in case no formatted query info present
                formattedQuery = new ObjectMapper().writeValueAsString(requestBody);
            }

        } catch (ClassCastException | JsonProcessingException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            logger.info("ACCESS_LOG ___ " + user.getUuid().toString() + "," + user.getEmail() + "," + user.getName() +
                    " ___ has been denied access to execute query ___ " + requestBody + " ___ in application ___ " + applicationName
                    + " ___ UNABLE TO PARSE REQUEST");
            return false;
        }

        Set<Privilege> privileges = user.getPrivilegesByApplication(application);

        // If the user doesn't have any privileges associated to the application,
        // it will return false. The logic is if there are any privileges associated with the application,
        // a user needs to have at least one privilege under the same application,
        // or be denied.
        // The check if the application has privileges or not should be outside this function.
        // Here we assume that the application has at least one privilege
        if (privileges == null || privileges.isEmpty()) {
            logger.info("ACCESS_LOG ___ " + user.getUuid().toString() + "," + user.getEmail() + "," + user.getName() +
                    " ___ has been denied access to execute query ___ " + formattedQuery + " ___ in application ___ " + applicationName
                    + " __ USER HAS NO PRIVILEGES ASSOCIATED TO THE APPLICATION, BUT APPLICATION HAS PRIVILEGES");
            return false;
        }

        Set<AccessRule> accessRules = this.accessRuleService.preProcessAccessRules(privileges);
        if (accessRules == null || accessRules.isEmpty()) {
            logger.info("ACCESS_LOG ___ " + user.getUuid().toString() + "," + user.getEmail() + "," + user.getName() +
                    " ___ has been granted access to execute query ___ " + formattedQuery + " ___ in application ___ " + applicationName
                    + " ___ NO ACCESS RULES EVALUATED");
            return true;
        }

        // loop through all accessRules
        // Current logic here is: among all accessRules, they are OR relationship
        Set<AccessRule> failedRules = new HashSet<>();
        AccessRule passByRule = null;
        boolean result = false;
        for (AccessRule accessRule : accessRules) {

            if (evaluateAccessRule(requestBody, accessRule)) {
                result = true;
                passByRule = accessRule;
                break;
            } else {
                failedRules.add(accessRule);
            }
        }

        String passRuleName = null;

        if (passByRule != null) {
            if (passByRule.getMergedName().isEmpty())
                passRuleName = passByRule.getName();
            else
                passRuleName = passByRule.getMergedName();
        }

        logger.info("ACCESS_LOG ___ {},{},{} ___ has been {} access to execute query ___ {} ___ in application ___ {} ___ {}", user.getUuid().toString(), user.getEmail(), user.getName(), result ? "granted" : "denied", formattedQuery, applicationName, result ? "passed by " + passRuleName : "failed by rules: ["
                + failedRules.stream()
                .map(ar -> (ar.getMergedName().isEmpty() ? ar.getName() : ar.getMergedName()))
                .collect(Collectors.joining(", ")) + "]");

        return result;
    }


    /**
     * inside one accessRule, it might contain a set of gates and a set of subAccessRule.
     * <br>
     * The default relationship between gates are AND. Gates are the first parts to be checked. If all the gates are passed,
     * it will start to check the rules. But relationship between gates could be set to OR.
     * <br>
     * All rules (rules and subAccessRules) under one accessRule are AND relationship .
     *
     * @param parsedRequestBody
     * @param accessRule
     * @return
     */
    public boolean evaluateAccessRule(Object parsedRequestBody, AccessRule accessRule) {
        logger.debug("evaluateAccessRule() starting with:");
        logger.debug(parsedRequestBody.toString());
        logger.debug("evaluateAccessRule()  access rule:{}", accessRule.getName());

        Set<AccessRule> gates = accessRule.getGates();

        // if no gates in this accessRule, this flag will be set to true
        // meaning the rules in this accessRule will be evaluated
        boolean gatesPassed = true;

        // depends on the flag getGateAnyRelation is true or false,
        // the logic of checking if apply gate will be changed
        // the following cases are gate passed:
        // 1. if gates are null or empty
        // 2. if getGateAnyRelation is false, all gates passed
        // 3. if getGateAnyRelation is true, one of the gate passed
        if (gates != null && !gates.isEmpty()) {
            if (accessRule.getGateAnyRelation() == null || !accessRule.getGateAnyRelation()) {

                // All gates are AND relationship
                // means one fails all fail
                for (AccessRule gate : gates) {
                    if (!evaluateAccessRule(parsedRequestBody, gate)) {
                        logger.error("evaluateAccessRule() gate {} failed ", gate.getName());
                        gatesPassed = false;
                        break;
                    }
                }
            } else {

                // All gates are OR relationship
                // means one passes all pass
                gatesPassed = false;
                for (AccessRule gate : gates) {
                    if (evaluateAccessRule(parsedRequestBody, gate)) {
                        logger.debug("evaluateAccessRule() gate {} passed ", gate.getName());
                        gatesPassed = true;
                        break;
                    }
                }
            }

        }

        // the result is based on if gates passed or not
        if (accessRule.getEvaluateOnlyByGates() != null && accessRule.getEvaluateOnlyByGates()) {
            logger.debug("evaluateAccessRule() eval only by gates");
            return gatesPassed;
        }

        if (gatesPassed) {
            logger.debug("evaluateAccessRule() gates passed");
            if (!extractAndCheckRule(accessRule, parsedRequestBody))
                return false;
            else {
                if (accessRule.getSubAccessRule() != null) {
                    for (AccessRule subAccessRule : accessRule.getSubAccessRule()) {
                        if (!extractAndCheckRule(subAccessRule, parsedRequestBody))
                            return false;
                    }
                }
            }
        } else {
            logger.debug("evaluateAccessRule() gates failed");
            // if gates not applied, this accessRule will consider deny
            return false;
        }

        return true;
    }

    /**
     * This function does two parts: extract the value from current node, then
     * call the evaluateNode() to check if it passed or not
     *
     * <br>
     * Note: if rule is empty, the check will always return true
     *
     * @param accessRule
     * @param parsedRequestBody
     * @return
     */
    boolean extractAndCheckRule(AccessRule accessRule, Object parsedRequestBody){
        logger.debug("extractAndCheckRule() starting");
        String rule = accessRule.getRule();

        if (rule == null || rule.isEmpty())
            return true;

        Object requestBodyValue;
        int accessRuleType = accessRule.getType();

        try {
            requestBodyValue = JsonPath.parse(parsedRequestBody).read(rule);
        } catch (PathNotFoundException ex) {
            //if path doesn't exist; that's enough to match 'is empty' rule.
            if (accessRuleType == AccessRule.TypeNaming.IS_EMPTY) {
                logger.debug("extractAndCheckRule() -> JsonPath.parse().read() PathNotFound;  passing IS_EMPTY rule");
                return true;
            }
            logger.debug("extractAndCheckRule() -> JsonPath.parse().read() throws exception with parsedRequestBody - {} : {} - {}", parsedRequestBody, ex.getClass().getSimpleName(), ex.getMessage());
            return false;
        }


        // AccessRule type IS_EMPTY is very special, needs to be checked in front of any others
        // in type IS_EMPTY, it doens't matter if the value is null or anything
        if (accessRuleType == AccessRule.TypeNaming.IS_EMPTY
                || accessRuleType == AccessRule.TypeNaming.IS_NOT_EMPTY) {
            if (requestBodyValue == null
                    || (requestBodyValue instanceof String && ((String) requestBodyValue).isEmpty())
                    || (requestBodyValue instanceof Collection && ((Collection) requestBodyValue).isEmpty())
                    || (requestBodyValue instanceof Map && ((Map) requestBodyValue).isEmpty())) {
                return accessRuleType == AccessRule.TypeNaming.IS_EMPTY;
            } else {
                return accessRuleType == AccessRule.TypeNaming.IS_NOT_EMPTY;
            }
        }

        return evaluateNode(requestBodyValue, accessRule);
    }


    private boolean evaluateNode(Object requestBodyValue, AccessRule accessRule) {
        logger.debug("evaluateNode() starting...");

        /*
         * NOTE: if the path(driven by attribute rule) eventually leads to String values, we can do check,
         * otherwise, only means the path is not driving to useful places, just return true.
         *
         * a possible requestBodyValue could be:
         *
         *     NOTE: this size 13 JSONArray contains every element in the root node,
         *     which means the parent node and child node will be separately counted, meaning
         *     13 elements contains duplicated but parent-child related nodes.
         *
         * requestBodyValue = {JSONArray@1560}  size = 13
         *  0 = {LinkedHashMap@1566}  size = 5
         *  1 = "8e8c7ed0-87ea-4342-b8da-f939e46bac26"
         *  2 = {LinkedHashMap@1568}  size = 0
         *  3 = {LinkedHashMap@1569}  size = 1
         *  4 = {LinkedHashMap@1570}  size = 0
         *  5 = {ArrayList@1571}  size = 1
         *  6 = "COUNT"
         *  7 = {ArrayList@1573}  size = 2
         *  8 = {ArrayList@1574}  size = 1
         *  9 = "male"
         *  10 = "\demographics\AGE\"
         *  11 = "\demographics\SEX\"
         *  12 = "\demographics\AGE\"
         */

        if (requestBodyValue instanceof String) {
            return decisionMaker(accessRule, (String) requestBodyValue);
        } else if (requestBodyValue instanceof Collection) {
            switch (accessRule.getType()) {
                case (AccessRule.TypeNaming.ANY_EQUALS):
                case (AccessRule.TypeNaming.ANY_CONTAINS):
                case (AccessRule.TypeNaming.ANY_REG_MATCH):
                    for (Object item : (Collection) requestBodyValue) {
                        if (item instanceof String) {
                            if (decisionMaker(accessRule, (String) item)) {
                                return true;
                            }
                        } else {
                            if (evaluateNode(item, accessRule)) {
                                return true;
                            }
                        }
                    }
                    // need to take care if the collection is empty
                    return false;
                default:
                    if (((Collection) requestBodyValue).isEmpty()) {
                        // need to take care if the collection is empty
                        switch (accessRule.getType()) {
                            case (AccessRule.TypeNaming.ALL_EQUALS_IGNORE_CASE):
                            case (AccessRule.TypeNaming.ALL_EQUALS):
                            case (AccessRule.TypeNaming.ALL_CONTAINS):
                            case (AccessRule.TypeNaming.ALL_CONTAINS_IGNORE_CASE):
                                // since collection is empty, nothing is complimented to the rule,
                                // it should return false
                                return false;
                            case (AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY):
                            case (AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY_IGNORE_CASE):
                            default:
                                // since collection is empty, nothing will be denied by the rule,
                                // so return true
                                return true;
                        }
                    }

                    for (Object item : (Collection) requestBodyValue) {
                        if (item instanceof String) {
                            if (!decisionMaker(accessRule, (String) item)) {
                                return false;
                            }
                        } else {
                            if (!evaluateNode(item, accessRule))
                                return false;
                        }
                    }
            }
        } else if (accessRule.getCheckMapNode() != null && accessRule.getCheckMapNode() && requestBodyValue instanceof Map) {
            switch (accessRule.getType()) {
                case (AccessRule.TypeNaming.ANY_EQUALS):
                case (AccessRule.TypeNaming.ANY_CONTAINS):
                case (AccessRule.TypeNaming.ANY_REG_MATCH):
                    for (Map.Entry entry : ((Map<String, Object>) requestBodyValue).entrySet()) {
                        if (decisionMaker(accessRule, (String) entry.getKey()))
                            return true;

                        if ((accessRule.getCheckMapKeyOnly() == null || !accessRule.getCheckMapKeyOnly())
                                && evaluateNode(entry.getValue(), accessRule))
                            return true;
                    }
                    return false;
                default:
                    if (((Map) requestBodyValue).isEmpty()) {
                        // need to take care if the collection is empty
                        switch (accessRule.getType()) {
                            case (AccessRule.TypeNaming.ALL_EQUALS_IGNORE_CASE):
                            case (AccessRule.TypeNaming.ALL_EQUALS):
                            case (AccessRule.TypeNaming.ALL_CONTAINS):
                            case (AccessRule.TypeNaming.ALL_CONTAINS_IGNORE_CASE):
                                // since collection is empty, nothing is complimented to the rule,
                                // it should return false
                                return false;
                            case (AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY):
                            case (AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY_IGNORE_CASE):
                            default:
                                // since collection is empty, nothing will be denied by the rule,
                                // so return true
                                return true;
                        }
                    }
                    for (Map.Entry entry : ((Map<String, Object>) requestBodyValue).entrySet()) {
                        if (!decisionMaker(accessRule, (String) entry.getKey()))
                            return false;

                        if ((accessRule.getCheckMapKeyOnly() == null || !accessRule.getCheckMapKeyOnly())
                                && !evaluateNode(entry.getValue(), accessRule))
                            return false;
                    }

            }

        }

        return true;
    }

    /**
     * The reason that the relationship between the mergedValues is OR is
     * the mergedValues actually come from merging multiple accessRules.
     * The relationship between multiple accessRules(=privileges/roles) is a OR relationship,
     * so as mergedValues sharing the same OR relationship
     *
     * <br><br>
     * Notice: all the values that need to be evaluated, will in accessRule.getMergedValues()
     * if the accessRule.getValue() is null, or accessRule.getMergedValues() is empty, meaning
     * it is a special case, which should be handle before the program hits this function
     *
     * @param accessRule
     * @param requestBodyValue
     * @return
     */
    boolean decisionMaker(AccessRule accessRule, String requestBodyValue){

        // it might be possible that sometimes there is value in the accessRule.getValue()
        // but the mergedValues doesn't have elements in it...
        if (accessRule.getMergedValues().isEmpty()) {
            String value = accessRule.getValue();
            if (value == null) {
                return requestBodyValue == null;
            }
            return _decisionMaker(accessRule, requestBodyValue, value);
        }


        // recursively check the values
        // until one of them is true
        // if there is only one element in the merged value set
        // the operation equals to _decisionMaker(accessRule, requestBodyValue, value)
        boolean res = false;
        for (String s : accessRule.getMergedValues()) {

            // check the special case value is null
            // if value is null, the check will stop here and
            // not goes to _decisionMaker()
            if (s == null) {
                if (requestBodyValue == null) {
                    res = true;
                    break;
                } else {
                    continue;
                }
            }

            // all the merged values are OR relationship
            // means if you pass one of them, you pass the rule
            if (_decisionMaker(accessRule, requestBodyValue, s)) {
                res = true;
                break;
            }
        }
        return res;
    }

    private boolean _decisionMaker(AccessRule accessRule, String requestBodyValue, String value) {
        logger.debug("_decisionMaker() starting");
        logger.debug("_decisionMaker() access rule:{}", accessRule.getName());
        logger.debug(requestBodyValue);
        logger.debug(value);

        return switch (accessRule.getType()) {
            case AccessRule.TypeNaming.NOT_CONTAINS -> !requestBodyValue.contains(value);
            case AccessRule.TypeNaming.NOT_CONTAINS_IGNORE_CASE -> !requestBodyValue.toLowerCase().contains(value.toLowerCase());
            case (AccessRule.TypeNaming.NOT_EQUALS) -> !value.equals(requestBodyValue);
            case (AccessRule.TypeNaming.ANY_EQUALS), (AccessRule.TypeNaming.ALL_EQUALS) ->
                    value.equals(requestBodyValue);
            case (AccessRule.TypeNaming.ALL_CONTAINS), (AccessRule.TypeNaming.ANY_CONTAINS),
                 (AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY) -> requestBodyValue.contains(value);
            case (AccessRule.TypeNaming.ALL_CONTAINS_IGNORE_CASE),
                 (AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY_IGNORE_CASE) -> requestBodyValue.toLowerCase().contains(value.toLowerCase());
            case (AccessRule.TypeNaming.NOT_EQUALS_IGNORE_CASE) -> !value.equalsIgnoreCase(requestBodyValue);
            case (AccessRule.TypeNaming.ALL_EQUALS_IGNORE_CASE) -> value.equalsIgnoreCase(requestBodyValue);
            case (AccessRule.TypeNaming.ALL_REG_MATCH), (AccessRule.TypeNaming.ANY_REG_MATCH) ->
                    requestBodyValue.matches(value);
            default -> {
                logger.warn("evaluateAccessRule() incoming accessRule type is out of scope. Just return true.");
                yield true;
            }
        };
    }

}
