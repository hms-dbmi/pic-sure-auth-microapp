package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.entity.AccessRule;
import edu.harvard.hms.dbmi.avillach.auth.repository.AccessRuleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ContextConfiguration;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

@SpringBootTest
@ContextConfiguration(classes = {AccessRuleService.class})
public class AccessRuleServiceTest {

    @MockBean
    private AccessRuleRepository accessRuleRepo;

    @Autowired
    private AccessRuleService accessRuleService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testGetAccessRuleById_found() {
        UUID id = UUID.randomUUID();
        AccessRule accessRule = new AccessRule();
        when(accessRuleRepo.findById(id)).thenReturn(Optional.of(accessRule));

        Optional<AccessRule> result = accessRuleService.getAccessRuleById(id.toString());
        assertTrue(result.isPresent());
        assertSame(accessRule, result.get());
    }

    @Test
    public void testGetAccessRuleById_notFound() {
        UUID id = UUID.randomUUID();
        when(accessRuleRepo.findById(id)).thenReturn(Optional.empty());

        Optional<AccessRule> result = accessRuleService.getAccessRuleById(id.toString());
        assertFalse(result.isPresent());
    }

    @Test
    public void testGetAllAccessRules_empty() {
        when(accessRuleRepo.findAll()).thenReturn(Collections.emptyList());

        List<AccessRule> result = accessRuleService.getAllAccessRules();
        assertTrue(result.isEmpty());
    }

    @Test
    public void testGetAllAccessRules_nonEmpty() {
        List<AccessRule> rules = Arrays.asList(new AccessRule(), new AccessRule());
        when(accessRuleRepo.findAll()).thenReturn(rules);

        List<AccessRule> result = accessRuleService.getAllAccessRules();
        assertEquals(2, result.size());
    }


    @Test
    public void testAddAccessRule_withNullFields() {
        AccessRule rule = new AccessRule(); // fields are null
        List<AccessRule> rules = Collections.singletonList(rule);
        when(accessRuleRepo.saveAll(anyList())).thenAnswer(invocation -> invocation.getArgument(0));

        List<AccessRule> result = accessRuleService.addAccessRule(rules);
        assertFalse(result.getFirst().getEvaluateOnlyByGates());
        assertFalse(result.getFirst().getCheckMapKeyOnly());
        assertFalse(result.getFirst().getCheckMapNode());
        assertFalse(result.getFirst().getGateAnyRelation());
    }

    @Test
    public void testAddAccessRule_noNullFields() {
        AccessRule rule = new AccessRule();
        rule.setEvaluateOnlyByGates(true);
        rule.setCheckMapKeyOnly(true);
        rule.setCheckMapNode(true);
        rule.setGateAnyRelation(true);
        List<AccessRule> rules = Collections.singletonList(rule);
        when(accessRuleRepo.saveAll(anyList())).thenReturn(rules);

        List<AccessRule> result = accessRuleService.addAccessRule(rules);
        assertTrue(result.getFirst().getEvaluateOnlyByGates());
        assertTrue(result.getFirst().getCheckMapKeyOnly());
        assertTrue(result.getFirst().getCheckMapNode());
        assertTrue(result.getFirst().getGateAnyRelation());
    }


    @Test
    public void testUpdateAccessRules() {
        AccessRule rule = new AccessRule();
        List<AccessRule> rules = Collections.singletonList(rule);
        when(accessRuleRepo.saveAll(anyList())).thenReturn(rules);

        List<AccessRule> result = accessRuleService.updateAccessRules(rules);
        assertSame(rules, result);
    }


    @Test
    public void testRemoveAccessRuleById() {
        UUID id = UUID.randomUUID();
        List<AccessRule> remainingRules = List.of(new AccessRule());
        doNothing().when(accessRuleRepo).deleteById(id);
        when(accessRuleRepo.findAll()).thenReturn(remainingRules);

        List<AccessRule> result = accessRuleService.removeAccessRuleById(id.toString());
        assertEquals(1, result.size());
    }

}