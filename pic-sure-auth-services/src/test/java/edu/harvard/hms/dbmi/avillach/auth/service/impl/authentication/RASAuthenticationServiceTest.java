package edu.harvard.hms.dbmi.avillach.auth.service.impl.authentication;

import com.fasterxml.jackson.core.JsonProcessingException;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasDbgapPermission;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.AccessRuleService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.RASPassPortService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.RoleService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.UserService;
import edu.harvard.hms.dbmi.avillach.auth.utils.RestClientUtil;
import junit.framework.TestCase;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.Base64;
import java.util.Set;

public class RASAuthenticationServiceTest extends TestCase {

    @Mock
    private UserService userService;

    @Mock
    private AccessRuleService accessRuleService;

    @Mock
    private RestClientUtil restClientUtil;

    @Mock
    private RoleService roleService;

    private RASPassPortService rasPassPortService;

    private RASAuthenticationService rasAuthenticationService;

    @Before
    public void setUp() throws Exception {
        rasAuthenticationService = new RASAuthenticationService(
                userService,
                accessRuleService,
                restClientUtil,
                false,
                "false",
                "false",
                "false",
                "false",
                roleService,
                rasPassPortService
            );

        // convert example ras passport to JsonNode



    }





}