package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.repository.ApplicationRepository;
import edu.harvard.hms.dbmi.avillach.auth.repository.PrivilegeRepository;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
import org.hibernate.PropertyNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.*;

@Service
public class ApplicationService extends BaseEntityService<Application> {

    private final static Logger logger = LoggerFactory.getLogger(ApplicationService.class);
    private final ApplicationRepository applicationRepo;
    private final PrivilegeRepository privilegeRepo;

    @Value("${application.client.secret}")
    private String CLIENT_SECRET;

    @Autowired
    protected ApplicationService(ApplicationRepository applicationRepo, PrivilegeRepository privilegeRepo) {
        super(Application.class);
        this.applicationRepo = applicationRepo;
        this.privilegeRepo = privilegeRepo;
    }

    /**
     * Retrieves an entity by its ID.
     *
     * @param applicationId the ID of the entity to retrieve
     * @return a ResponseEntity representing the result of the operation
     */
    public ResponseEntity<?> getEntityById(String applicationId) {
        return getEntityById(applicationId, applicationRepo);
    }

    public ResponseEntity<?> getEntityAll() {
        return getEntityAll(applicationRepo);
    }

    @Transactional
    public ResponseEntity<?> addNewApplications(List<Application> applications) {
        checkAssociation(applications);
        List<Application> appEntities = addOrUpdate(applications, true, applicationRepo);
        for (Application application : appEntities) {
            try {
                application.setToken(
                        generateApplicationToken(application)
                );
            } catch (Exception e) {
                logger.error("", e);
            }
        }

        return updateEntity(appEntities, applicationRepo);
    }

    @Transactional
    public ResponseEntity<?> deleteApplicationById(String applicationId) {
        Application application = applicationRepo.getById(UUID.fromString(applicationId));
        if (application == null) {
            logger.error("deleteApplicationById() cannot find the application by applicationId: " + applicationId);
            throw new IllegalArgumentException("Cannot find application by the given applicationId: " + applicationId);
        }

        return removeEntityById(applicationId, applicationRepo);
    }

    public ResponseEntity<?> updateApplications(List<Application> applications) {
        checkAssociation(applications);
        return updateEntity(applications, applicationRepo);
    }

    public ResponseEntity<?> refreshApplicationToken(String applicationId) {
        Application application = applicationRepo.getById(UUID.fromString(applicationId));
        if (application == null) {
            logger.error("refreshApplicationToken() cannot find the application by applicationId: " + applicationId);
            throw new IllegalArgumentException("Cannot find application by the given applicationId: " + applicationId);
        }

        String newApplicationToken = generateApplicationToken(application);
        try {
            application.setToken(
                    newApplicationToken
            );

            applicationRepo.merge(application);
        } catch (Exception e) {
            logger.error("", e);
        }

        return PICSUREResponse.success(Map.of("token", newApplicationToken));
    }

    private void checkAssociation(List<Application> applications) { //TODO: We need to refactor this into a service class
        for (Application application : applications) {
            if (application.getPrivileges() != null) {
                Set<Privilege> privileges = new HashSet<>();
                application.getPrivileges().forEach(p -> {
                    Privilege privilege = privilegeRepo.getById(p.getUuid());
                    if (privilege != null) {
                        privilege.setApplication(application);
                        privileges.add(privilege);
                    } else {
                        logger.error("Didn't find privilege by uuid: " + p.getUuid());
                    }
                });
                application.setPrivileges(privileges);

            }
        }
    }

    public String generateApplicationToken(Application application) { // TODO: Refactor this into a new service class
        if (application == null || application.getUuid() == null) {
            logger.error("generateApplicationToken() application is null or uuid is missing to generate the application token");
            throw new PropertyNotFoundException("Cannot generate application token, please contact admin");
        }

        return JWTUtil.createJwtToken(
                this.CLIENT_SECRET, null, null,
                new HashMap<>(
                        Map.of(
                                "user_id", AuthNaming.PSAMA_APPLICATION_TOKEN_PREFIX + "|" + application.getName()
                        )
                ),
                AuthNaming.PSAMA_APPLICATION_TOKEN_PREFIX + "|" + application.getUuid().toString(), 365L * 1000 * 60 * 60 * 24);
    }

}

