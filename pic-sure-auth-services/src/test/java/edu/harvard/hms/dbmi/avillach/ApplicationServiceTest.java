package edu.harvard.hms.dbmi.avillach;

import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.ApplicationService;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import java.util.UUID;

public class ApplicationServiceTest {

    @Mock
    private ApplicationService applicationService;

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
