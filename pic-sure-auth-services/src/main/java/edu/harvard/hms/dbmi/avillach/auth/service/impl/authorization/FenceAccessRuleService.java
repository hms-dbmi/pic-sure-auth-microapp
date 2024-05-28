package edu.harvard.hms.dbmi.avillach.auth.service.impl.authorization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import edu.harvard.hms.dbmi.avillach.auth.entity.AccessRule;
import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.repository.AccessRuleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class FenceAccessRuleService {

    private final Logger logger = LoggerFactory.getLogger(FenceAccessRuleService.class);

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final AccessRuleRepository accessRuleRepository;

    @Autowired
    public FenceAccessRuleService(AccessRuleRepository accessRuleRepository) {
        this.accessRuleRepository = accessRuleRepository;
    }

    @Cacheable(value = "fenceMergedRulesCache", key = "#user.getEmail()")
    public Set<AccessRule> getFenceAccessRulesForUserAndApp(User user, Application application) {
        try {
            Set<Privilege> privileges = user.getPrivilegesByApplication(application);

            // If the user doesn't have any privileges associated to the application,
            // it will return null. The logic is if there are any privileges associated with the application,
            // a user needs to have at least one privilege under the same application, or be denied.
            if (privileges == null || privileges.isEmpty()) {
                return null;
            }

            //since we are caching these objects, we need to detach them from hibernate
            Set<AccessRule> detachedMergedRules = new HashSet<AccessRule>();
            for(AccessRule rule : preProcessAccessRules(privileges)) {
                detachedMergedRules.add(objectMapper.readValue(objectMapper.writeValueAsString(rule), AccessRule.class));
            }

            return detachedMergedRules;
        } catch (Exception e) {
            logger.error("error populating or retrieving data from cache: ", e);
        }

        return null;
    }

    @CacheEvict(value = "mergedRulesCache", key = "#user.getEmail()")
    public void evictFromCache(User user) {
        // This method is used to clear the cache for a user when their privileges are updated
    }

    /**
     * This class is for preparing for a set of accessRule that used by the further checking
     * Currently it contains a merge function
     *
     * @param privileges the privileges that need to be checked
     * @return the merged accessRules
     */
    private Set<AccessRule> preProcessAccessRules(Set<Privilege> privileges){
        logger.debug("preProcessAccessRules() merging rules");
        Set<AccessRule> accessRules = new HashSet<>();
        for (Privilege privilege : privileges) {
            accessRules.addAll(privilege.getAccessRules());
        }

        // now we use the function preProcess by sorted string keys
        // if needed, we could implement another function to sort by other key or combination of keys
        return preProcessARBySortedKeys(accessRules);
    }

    /**
     * This function is doing the merge by gathering all String keys together
     * and sorted to be the key in the map
     *
     * @param accessRules the accessRules that need to be merged
     * @return Merge the accessRules by sorted keys
     */
    protected Set<AccessRule> preProcessARBySortedKeys(Set<AccessRule> accessRules){
        // key is a combination of uuid of gates and rule
        // value is a list of the same key accessrule,
        // later will be merged to be new AccessRule for evaluation
        Map<String, Set<AccessRule>> accessRuleMap  = new HashMap<>();

        for (AccessRule accessRule : accessRules) {

            // 1st generate the key by grabbing all related string and put them together in order
            // we use a treeSet here to put orderly combine Strings together
            Set<String> keys = new TreeSet<>();

            // the current accessRule rule
            keys.add(accessRule.getRule());

            // the accessRule type
            keys.add(accessRule.getType().toString());

            // all gates' UUID as strings
            if (accessRule.getGates() != null) {
                for (AccessRule gate : accessRule.getGates()){
                    keys.add(gate.getUuid().toString());
                }
            }

            // all sub accessRule rules
            if (accessRule.getSubAccessRule() != null){
                for (AccessRule subAccessRule : accessRule.getSubAccessRule()){
                    keys.add(subAccessRule.getRule());
                }
            }
            Boolean checkMapKeyOnly = accessRule.getCheckMapKeyOnly(),
                    checkMapNode = accessRule.getCheckMapNode(),
                    evaluateOnlyByGates = accessRule.getEvaluateOnlyByGates(),
                    gateAnyRelation = accessRule.getGateAnyRelation();

            keys.add(checkMapKeyOnly==null?"null":Boolean.toString(checkMapKeyOnly));
            keys.add(checkMapNode==null?"null":Boolean.toString(checkMapNode));
            keys.add(evaluateOnlyByGates==null?"null":Boolean.toString(evaluateOnlyByGates));
            keys.add(gateAnyRelation==null?"null":Boolean.toString(gateAnyRelation));

            // then we combine them together as one string for the key
            String key = keys.stream().collect(Collectors.joining());
            logger.trace("Rule Key " + accessRule.getName() + ": " + key);
            // put it into the accessRuleMap
            if (accessRuleMap.containsKey(key)){
                accessRuleMap.get(key).add(accessRule);
            } else {
                Set<AccessRule> accessRuleSet = new HashSet<>();
                accessRuleSet.add(accessRule);
                accessRuleMap.put(key, accessRuleSet);
            }
        }


        return mergeSameKeyAccessRules(accessRuleMap.values());
    }

    /**
     * merge accessRules in the same collection into one accessRule
     * <br>
     * The accessRules in the same collection means they shared the same
     * standard and can be merged together
     *
     * @param accessRuleMap the map that contains the accessRules
     * @return the merged accessRules
     */
    private Set<AccessRule> mergeSameKeyAccessRules(Collection<Set<AccessRule>> accessRuleMap){
        Set<AccessRule> accessRules = new HashSet<>();
        logger.debug("AccessRuleMap has " + accessRuleMap.size() + " entries");
        for (Set<AccessRule> accessRulesSet : accessRuleMap) {
            // merge one set of accessRule into one accessRule
            AccessRule accessRule = null;
            for (AccessRule innerAccessRule : accessRulesSet){
                accessRule = mergeAccessRules(accessRule, innerAccessRule);
            }
            // if the new merged accessRule exists, add it into the final result set
            if (accessRule != null) {
                accessRules.add(accessRule);
            }
        }

        return accessRules;
    }

    /**
     * Notice: we don't need to worry about if any accessRule value is null
     * since the mergedValues is a Set, it allows adding null value,
     * and later on when doing evaluation, this null value will be handled
     *
     * @param baseAccessRule the base accessRule and this will be returned
     * @param accessRuleToBeMerged the one that waits to be merged into base accessRule
     * @return
     */
    private AccessRule mergeAccessRules(AccessRule baseAccessRule, AccessRule accessRuleToBeMerged){
        if (baseAccessRule == null) {
            accessRuleToBeMerged.getMergedValues().add(accessRuleToBeMerged.getValue());
            return accessRuleToBeMerged;
        }

        if (baseAccessRule.getSubAccessRule()!= null && accessRuleToBeMerged.getSubAccessRule() != null){
            baseAccessRule.getSubAccessRule().addAll(accessRuleToBeMerged.getSubAccessRule());
        } else if (baseAccessRule.getSubAccessRule() == null && accessRuleToBeMerged.getSubAccessRule() != null){
            baseAccessRule.setSubAccessRule(accessRuleToBeMerged.getSubAccessRule());
        }

        baseAccessRule.getMergedValues().add(accessRuleToBeMerged.getValue());
        if (baseAccessRule.getMergedName().startsWith("Merged|")){
            baseAccessRule.setMergedName(baseAccessRule.getMergedName() +"|"+ accessRuleToBeMerged.getName());
        } else {
            baseAccessRule.setMergedName("Merged|" + baseAccessRule.getName() + "|"+ accessRuleToBeMerged.getName());
        }


        return baseAccessRule;
    }

    /**
     * inside one accessRule, it might contain a set of gates and a set of subAccessRule.
     * <br>
     * The default relationship between gates are AND. Gates are the first parts to be checked. If all the gates are passed,
     * it will start to check the rules. But relationship between gates could be set to OR.
     * <br>
     * All rules (rules and subAccessRules) under one accessRule are AND relationship .
     *
     * @param requestBody
     * @param accessRule
     * @return
     */
    protected boolean evaluateAccessRule(Object requestBody, AccessRule accessRule) {
//	    logger.debug("evaluateAccessRule() starting with:");
//	    logger.debug(parsedRequestBody.toString());
        logger.debug("evaluateAccessRule() (possibly merged) access rule: "+accessRule.getName());

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
            if (accessRule.getGateAnyRelation() == null || accessRule.getGateAnyRelation() == false) {
                logger.debug("checking AND gates ");
                // All gates are AND relationship
                // means one fails all fail
                for (AccessRule gate : gates){
                    if (!evaluateAccessRule(requestBody, gate)){
                        logger.error("evaluateAccessRule() gate "+gate.getName()+" failed: " + gate.getRule() + " ____ " + gate.getValue());
                        gatesPassed = false;
                        break;
                    }
                }
                if(gatesPassed) {
                    logger.debug("all AND gates passed");
                }
            } else {
                logger.debug("checking OR gates ");
                // All gates are OR relationship
                // means one passes all pass
                gatesPassed = false;
                for (AccessRule gate : gates){
                    if (evaluateAccessRule(requestBody, gate)){
                        logger.debug("evaluateAccessRule() gate "+gate.getName()+" passed ");
                        gatesPassed = true;
                        break;
                    }
                }
                if(!gatesPassed) {
                    logger.debug("all OR gates failed");
                }
            }
        }

        // the result is based on if gates passed or not
        if (accessRule.getEvaluateOnlyByGates() != null && accessRule.getEvaluateOnlyByGates()){
            logger.debug("evaluateAccessRule() eval only by gates.  result:" + gatesPassed);
            return gatesPassed;
        }

        if (gatesPassed) {
//        	logger.debug("Gates passed.  Request Body: " + requestBody);
            if (extractAndCheckRule(accessRule, requestBody) == false) {
                logger.debug("Query Rejected by rule(1) " + accessRule.getRule() + " :: " + accessRule.getType() + " :: " + accessRule.getValue() );
                return false;
            }
            else {
                if (accessRule.getSubAccessRule() != null) {
                    //Now we neeed to merge the sub rules; they can overlap as well!
                    Set<AccessRule> mergedSubRules = preProcessARBySortedKeys(accessRule.getSubAccessRule());
                    for (AccessRule subAccessRule : mergedSubRules) {
                        if (extractAndCheckRule(subAccessRule, requestBody) == false) {
                            logger.debug("Query Rejected by rule(2) " + subAccessRule.getRule() + " :: " + subAccessRule.getType() + " :: " + subAccessRule.getValue() );
                            return false;
                        }
                    }
                }
            }
            return true;
        }

        // if gates not applied, this accessRule will consider deny
        logger.debug("Gates failed for (possibly merged) " + accessRule.getName());

        return false;
    }

    /**
     * This function does two parts: extract the value from current node, then
     * call the evaluateNode() to check if it passed or not
     *
     * <br>
     * Note: if rule is empty, the check will always return true
     *
     * @param accessRule
     * @param requestBody
     * @return
     */
    private boolean extractAndCheckRule(AccessRule accessRule, Object requestBody) {
        String rule = accessRule.getRule();

        if (rule == null || rule.isEmpty()) {
            return true;
        }

        JsonNode parsedRequest;
        int accessRuleType = accessRule.getType();

        try {
            logger.debug("extractAndCheckRule() {}: rule: {}", accessRule.getMergedName(), rule);
            Object result = JsonPath.parse(requestBody).read(rule);

            // Convert the result to a JsonNode
            parsedRequest = objectMapper.valueToTree(result);

            // JSONPath always returns a list even when we want a map (to check keys)
            // so here's some code to handle that!
            if (accessRule.getCheckMapNode()) {
                if (parsedRequest.isArray() && parsedRequest.size() == 1 && parsedRequest.get(0).isObject()) {
                    parsedRequest = parsedRequest.get(0);
                }
            }
        } catch (PathNotFoundException ex) {
            // If path doesn't exist; that's enough to match 'is empty' rule
            logger.debug("extractAndCheckRule() -> JsonPath.parse().read() throws exception with parsedRequestBody - {} : {} - {}", requestBody, ex.getClass().getSimpleName(), ex.getMessage());
            return accessRuleType == AccessRule.TypeNaming.IS_EMPTY;
        } catch (Exception e) {
            logger.error("Error parsing JSON: {}", e.getMessage(), e);
            return false;
        }

        // AccessRule type IS_EMPTY is very special, needs to be checked in front of any others
        // In type IS_EMPTY, it doesn't matter if the value is null or anything
        if (accessRuleType == AccessRule.TypeNaming.IS_EMPTY || accessRuleType == AccessRule.TypeNaming.IS_NOT_EMPTY) {
            if (parsedRequest == null
                    || (parsedRequest.isTextual() && parsedRequest.asText().isEmpty())
                    || (parsedRequest.isArray() && parsedRequest.isEmpty())
                    || (parsedRequest.isObject() && parsedRequest.size() == 0)) {
                return accessRuleType == AccessRule.TypeNaming.IS_EMPTY;
            } else {
                return accessRuleType == AccessRule.TypeNaming.IS_NOT_EMPTY;
            }
        }

        return evaluateNode(parsedRequest, accessRule);
    }


    private boolean evaluateNode(Object requestBodyValue, AccessRule accessRule){
        logger.debug("evaluateNode() starting: " + accessRule.getRule() + " :: " + accessRule.getType() + " :: "
                + (accessRule.getMergedValues().isEmpty() ? accessRule.getValue() : ("Merged " + Arrays.deepToString(accessRule.getMergedValues().toArray()))));
        logger.trace("evaluateNode() requestBody " + requestBodyValue.getClass().getName() + "  " +
                (requestBodyValue instanceof Collection ?
                        Arrays.deepToString(((Collection)requestBodyValue).toArray()) :
                        requestBodyValue.toString()));
        /**
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

        if (requestBodyValue instanceof String){
            return decisionMaker(accessRule, (String)requestBodyValue);
        } else if (requestBodyValue instanceof Collection) {
            switch (accessRule.getType()){
                case (AccessRule.TypeNaming.ANY_EQUALS):
                case (AccessRule.TypeNaming.ANY_CONTAINS):
                case(AccessRule.TypeNaming.ANY_REG_MATCH):
                    for (Object item : (Collection)requestBodyValue) {
                        if (item instanceof String){
                            if (decisionMaker(accessRule, (String)item)){
                                return true;
                            }
                        } else {
                            if (evaluateNode(item, accessRule)){
                                return true;
                            }
                        }
                    }
                    return false;
                default:
                    if (((Collection) requestBodyValue).isEmpty()){
                        // need to take care if the collection is empty
                        switch (accessRule.getType()){
                            case (AccessRule.TypeNaming.ALL_EQUALS_IGNORE_CASE):
                            case (AccessRule.TypeNaming.ALL_EQUALS):
                            case (AccessRule.TypeNaming.ALL_CONTAINS):
                            case (AccessRule.TypeNaming.ALL_CONTAINS_IGNORE_CASE):
                                // since collection is empty, nothing is complimented to the rule,
                                // it should return false
                                return false;
                            case(AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY):
                            case (AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY_IGNORE_CASE):
                            default:
                                // since collection is empty, nothing will be denied by the rule,
                                // so return true
                                return true;
                        }
                    }

                    for (Object item : (Collection)requestBodyValue){
                        if (item instanceof String) {
                            if (decisionMaker(accessRule, (String)item) == false){
                                return false;
                            }
                        } else {
                            if (evaluateNode(item, accessRule) == false)
                                return false;
                        }
                    }
            }
        } else if (accessRule.getCheckMapNode() != null && accessRule.getCheckMapNode() && requestBodyValue instanceof Map) {
            switch (accessRule.getType()) {
                case (AccessRule.TypeNaming.ANY_EQUALS):
                case (AccessRule.TypeNaming.ANY_CONTAINS):
                case(AccessRule.TypeNaming.ANY_REG_MATCH):
                    for (Map.Entry entry : ((Map<String, Object>) requestBodyValue).entrySet()){
                        if (decisionMaker(accessRule, (String) entry.getKey()))
                            return true;

                        if((accessRule.getCheckMapKeyOnly() == null || !accessRule.getCheckMapKeyOnly())
                                && evaluateNode(entry.getValue(), accessRule))
                            return true;
                    }
                    return false;
                default:
                    if (((Map) requestBodyValue).isEmpty()){
                        // need to take care if the collection is empty
                        switch (accessRule.getType()){
                            case (AccessRule.TypeNaming.ALL_EQUALS_IGNORE_CASE):
                            case (AccessRule.TypeNaming.ALL_EQUALS):
                            case (AccessRule.TypeNaming.ALL_CONTAINS):
                            case (AccessRule.TypeNaming.ALL_CONTAINS_IGNORE_CASE):
                                // since collection is empty, nothing is complimented to the rule,
                                // it should return false
                                return false;
                            case(AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY):
                            case (AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY_IGNORE_CASE):
                            default:
                                // since collection is empty, nothing will be denied by the rule,
                                // so return true
                                return true;
                        }
                    }
                    for (Map.Entry entry : ((Map<String, Object>) requestBodyValue).entrySet()){
                        if (decisionMaker(accessRule, (String) entry.getKey()) == false)
                            return false;

                        if( (accessRule.getCheckMapKeyOnly() == null || !accessRule.getCheckMapKeyOnly())
                                && evaluateNode(entry.getValue(), accessRule) == false)
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
    private boolean decisionMaker(AccessRule accessRule, String requestBodyValue){
        // it might be possible that sometimes there is value in the accessRule.getValue()
        // but the mergedValues doesn't have elements in it...
        if (accessRule.getMergedValues().isEmpty()){
            String value = accessRule.getValue();
            logger.trace("No merged values, deciding on" + value + " :: " + requestBodyValue);
            if (value == null){
                if (requestBodyValue == null) {
                    return true;
                } else {
                    return false;
                }
            }
            return _decisionMaker(accessRule, requestBodyValue, value);
        }


        // recursively check the values
        // until one of them is true
        // if there is only one element in the merged value set
        // the operation equals to _decisionMaker(accessRule, requestBodyValue, value)
        boolean res = false;
        if(logger.isTraceEnabled())
            logger.trace("checking " + requestBodyValue + " in collection " + Arrays.deepToString(accessRule.getMergedValues().toArray()));
        for (String s : accessRule.getMergedValues()){

            // check the special case value is null
            // if value is null, the check will stop here and
            // not goes to _decisionMaker()
            if (s == null){
                if (requestBodyValue == null) {
                    res = true;
                    break;
                } else {
                    res = false;
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

    private boolean _decisionMaker(AccessRule accessRule, String requestBodyValue, String value){

//        logger.trace("_decisionMaker() checking for value " + value + " in " + requestBodyValue);

        switch (accessRule.getType()){
            case AccessRule.TypeNaming.NOT_CONTAINS:
                if (!requestBodyValue.contains(value))
                    return true;
                else
                    return false;
            case AccessRule.TypeNaming.NOT_CONTAINS_IGNORE_CASE:
                if (!requestBodyValue.toLowerCase().contains(value.toLowerCase()))
                    return true;
                else
                    return false;
            case(AccessRule.TypeNaming.NOT_EQUALS):
                if (!value.equals(requestBodyValue))
                    return true;
                else
                    return false;
            case(AccessRule.TypeNaming.ANY_EQUALS):
            case(AccessRule.TypeNaming.ALL_EQUALS):
                if (value.equals(requestBodyValue))
                    return true;
                else
                    return false;
            case(AccessRule.TypeNaming.ALL_CONTAINS):
            case(AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY):
            case(AccessRule.TypeNaming.ANY_CONTAINS):
                if (requestBodyValue.contains(value))
                    return true;
                else
                    return false;
            case(AccessRule.TypeNaming.ALL_CONTAINS_IGNORE_CASE):
            case (AccessRule.TypeNaming.ALL_CONTAINS_OR_EMPTY_IGNORE_CASE):
                if (requestBodyValue.toLowerCase().contains(value.toLowerCase()))
                    return true;
                else
                    return false;
            case(AccessRule.TypeNaming.NOT_EQUALS_IGNORE_CASE):
                if (!value.equalsIgnoreCase(requestBodyValue))
                    return true;
                else
                    return false;
            case(AccessRule.TypeNaming.ALL_EQUALS_IGNORE_CASE):
                if (value.equalsIgnoreCase(requestBodyValue))
                    return true;
                else
                    return false;
            case(AccessRule.TypeNaming.ALL_REG_MATCH):
            case(AccessRule.TypeNaming.ANY_REG_MATCH):
                if (requestBodyValue.matches(value))
                    return true;
                else
                    return false;
            case(AccessRule.TypeNaming.IS_EMPTY):

            default:
                logger.warn("evaluateAccessRule() incoming accessRule type is out of scope. Just return true.");
                return true;
        }
    }


    public AccessRule getAccessRuleByName(String arName) {
        return this.accessRuleRepository.findByName(arName);
    }

    public AccessRule save(AccessRule ar) {
        return this.accessRuleRepository.save(ar);
    }
}
