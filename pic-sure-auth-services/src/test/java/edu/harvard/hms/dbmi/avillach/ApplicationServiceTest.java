package edu.harvard.hms.dbmi.avillach;

import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.repository.ApplicationRepository;
import edu.harvard.hms.dbmi.avillach.auth.repository.PrivilegeRepository;
import edu.harvard.hms.dbmi.avillach.auth.service.PrivilegeService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.ApplicationService;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.UUID;

@RunWith(MockitoJUnitRunner.class)
public class ApplicationServiceTest {

    @InjectMocks
    private ApplicationService applicationService;

    @Mock
    private PrivilegeRepository privilegeRepository;

    @Mock
    private ApplicationRepository applicationRepository;

    @Before
    public void init() {
    }

    @Test
    public void testGenerateToken(){
        Application application = new Application();
        application.setUuid(UUID.randomUUID());
        application.setName("Testing Application");
        application.setUrl("https://psama.hms.harvard.edu");

        String token = applicationService.generateApplicationToken(application);

        Assert.assertNotNull("Token is null, given application: " + application.getUuid(), token);
        Assert.assertTrue("Token is too short",token.length() > 10);
    }
}
