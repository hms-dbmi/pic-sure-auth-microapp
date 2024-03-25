package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.entity.AccessRule;
import edu.harvard.hms.dbmi.avillach.auth.repository.AccessRuleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;

@Service
public class AccessRuleService extends BaseEntityService<AccessRule>{

    private final AccessRuleRepository accessRuleRepo;

    @Autowired
    protected AccessRuleService(Class<AccessRule> type, AccessRuleRepository accessRuleRepo) {
        super(type);
        this.accessRuleRepo = accessRuleRepo;
    }


    public ResponseEntity<?> getEntityById(String accessRuleId) {
        return getEntityById(accessRuleId, accessRuleRepo);
    }

    public ResponseEntity<?> getEntityAll() {
        return getEntityAll(accessRuleRepo);
    }

    public ResponseEntity<?> addEntity(List<AccessRule> accessRules) {
        accessRules.forEach(accessRule -> {
            if (accessRule.getEvaluateOnlyByGates() == null)
                accessRule.setEvaluateOnlyByGates(false);

            if (accessRule.getCheckMapKeyOnly() == null)
                accessRule.setCheckMapKeyOnly(false);

            if (accessRule.getCheckMapNode() == null)
                accessRule.setCheckMapNode(false);

            if (accessRule.getGateAnyRelation() == null)
                accessRule.setGateAnyRelation(false);
        });

        return addEntity(accessRules, accessRuleRepo);
    }

    public ResponseEntity<?> updateEntity(List<AccessRule> accessRules) {
        return updateEntity(accessRules, accessRuleRepo);
    }

    @Transactional
    public ResponseEntity<?> removeEntityById(String accessRuleId) {
        return removeEntityById(accessRuleId, accessRuleRepo);
    }
}
