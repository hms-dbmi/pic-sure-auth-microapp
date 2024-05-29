package edu.harvard.hms.dbmi.avillach.auth.service.impl.authorization;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.hms.dbmi.avillach.auth.entity.AccessRule;
import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class FenceAuthorizationService {

    private final Logger logger = LoggerFactory.getLogger(AuthorizationService.class);

    private final MergedAccessRuleService fenceAccessRuleService;

    @Autowired
    public FenceAuthorizationService(MergedAccessRuleService fenceAccessRuleService) {
        this.fenceAccessRuleService = fenceAccessRuleService;
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
     *
     * @param application the application to check against
     * @param requestBody the request body to check against
     * @return true if the user is authorized, false otherwise
     *
     * @see edu.harvard.hms.dbmi.avillach.auth.entity.Privilege
     * @see AccessRule
     */
    public boolean isAuthorized(Application application , Object requestBody, User user) {
        boolean authorized = _isAuthorized(application, requestBody, user);
        if(!authorized) {
            logger.warn("isAuthorized() User {} not authorized, clearing merged rules entry", user.getEmail());
            this.fenceAccessRuleService.evictFromCache(user);
        }
        return authorized;
    }


    private boolean _isAuthorized(Application application , Object requestBody, User user){

        String applicationName = application.getName();

        String resourceId = "null";
        String targetService = "null";

        //in some cases, we don't go through the evaluation
        if (requestBody == null) {
            logger.info("ACCESS_LOG ___ " + user.getUuid().toString() + "," + user.getEmail() + "," + user.getName() +
                    " ___ has been granted access to application ___ " + applicationName +
                    " ___  resource ___ " + resourceId + " ___ targetService ___ " + targetService +
                    " ___ NO REQUEST BODY FORWARDED BY APPLICATION");
            return true;
        }

        try {
            Map requestBodyMap = (Map) requestBody;
            Map queryMap = (Map) requestBodyMap.get("query");
            resourceId = (String) queryMap.get("resourceUUID");
            targetService = (String) requestBodyMap.get("Target Service");
        } catch (RuntimeException e) {
            logger.info("Error parsing resource and target service from requestBody", e);
        }

        // start to process the jsonpath checking
        String formattedQuery = null;
        try {
            // NC - this formatted query can sometimes mask data, but it's just used for logging
            formattedQuery = (String) ((Map)requestBody).get("formattedQuery");

            if(formattedQuery == null) {
                //fallback in case no formatted query info present
                formattedQuery = new ObjectMapper().writeValueAsString(requestBody);
            }
        } catch (ClassCastException | JsonProcessingException e1) {
            logger.info("ACCESS_LOG ___ {},{},{} ___ has been denied access to execute query ___ {} ___ in application ___ {} ___  resource ___ {} ___ targetService ___ {} ___ UNABLE TO PARSE REQUEST", user.getUuid().toString(), user.getEmail(), user.getName(), requestBody, applicationName, resourceId, targetService);
            return false;
        }

        Set<AccessRule> accessRules = this.fenceAccessRuleService.getAccessRulesForUserAndApp(user, application);
        if(accessRules == null || accessRules.isEmpty()) {
            logger.info("ACCESS_LOG ___ {},{},{} ___ has been denied access to execute query ___ {} ___ in application ___ {} ___  resource ___ {} ___ targetService ___ {} ___ NO ACCESS RULES EVALUATED", user.getUuid().toString(), user.getEmail(), user.getName(), formattedQuery, applicationName, resourceId, targetService);
            return false;
        }

        // loop through all accessRules
        // Current logic here is: among all accessRules, they are OR relationship
        Set<AccessRule> failedRules = new HashSet<>();
        AccessRule passByRule = null;
        boolean result = false;

        logger.debug("REQUEST: {}", requestBody);
        for (AccessRule accessRule : accessRules) {

            if (this.fenceAccessRuleService.evaluateAccessRule(requestBody, accessRule)){
                logger.debug("accessRule {}GRANTS ACCESS", accessRule.getMergedName());
                result = true;
                passByRule = accessRule;
                break;
            } else {
                logger.warn("accessRule {}FAILS", accessRule.getName());
                failedRules.add(accessRule);
            }
        }

        String passRuleName = null;

        if (passByRule != null){
            if (passByRule.getMergedName().isEmpty())
                passRuleName = passByRule.getName();
            else
                passRuleName = passByRule.getMergedName();
        }

        logger.info("ACCESS_LOG ___ {},{},{} ___ has been {} access to execute query ___ {} ___ in application ___ {} ___  resource ___ {} ___ targetService ___ {} ___ {}", user.getUuid().toString(), user.getEmail(), user.getName(), result ? "granted" : "denied", formattedQuery, applicationName, resourceId, targetService, result ? "passed by " + passRuleName : "failed by rules: ["
                + failedRules.stream()
                .map(ar -> (ar.getMergedName().isEmpty() ? ar.getName() : ar.getMergedName()))
                .collect(Collectors.joining(", ")) + "]");

        return result;
    }



}
