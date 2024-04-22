package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.repository.ApplicationRepository;
import edu.harvard.hms.dbmi.avillach.auth.repository.PrivilegeRepository;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
public class ApplicationService {

    private final static Logger logger = LoggerFactory.getLogger(ApplicationService.class);
    private final ApplicationRepository applicationRepo;
    private final PrivilegeRepository privilegeRepo;

    @Value("${application.client.secret}")
    private String CLIENT_SECRET;

    @Autowired
    ApplicationService(ApplicationRepository applicationRepo, PrivilegeRepository privilegeRepo) {
        this.applicationRepo = applicationRepo;
        this.privilegeRepo = privilegeRepo;
    }

    /**
     * Retrieves an entity by its ID.
     *
     * @param applicationId the ID of the entity to retrieve
     * @return a ResponseEntity representing the result of the operation
     */
    public Optional<Application> getApplicationByID(String applicationId) {
        return this.applicationRepo.findById(UUID.fromString(applicationId));
    }

    public List<Application> getAllApplications() {
        return this.applicationRepo.findAll();
    }

    @Transactional
    public List<Application> addNewApplications(List<Application> applications) {
        checkAssociation(applications);
        List<Application> appEntities = this.applicationRepo.saveAll(applications);
        for (Application application : appEntities) {
            try {
                application.setToken(
                        generateApplicationToken(application)
                );
            } catch (Exception e) {
                logger.error("", e);
            }
        }

        return this.applicationRepo.saveAll(appEntities);
    }

    @Transactional
    public List<Application> deleteApplicationById(String applicationId) {
        Optional<Application> application = applicationRepo.findById(UUID.fromString(applicationId));

        if (application.isEmpty()) {
            logger.error("deleteApplicationById() cannot find the application by applicationId: {}", applicationId);
            throw new IllegalArgumentException("Cannot find application by the given applicationId: " + applicationId);
        }

        this.applicationRepo.delete(application.get());
        return this.applicationRepo.findAll();
    }

    public List<Application> updateApplications(List<Application> applications) {
        checkAssociation(applications);
        return this.applicationRepo.saveAll(applications);
    }

    public String refreshApplicationToken(String applicationId) {
        Optional<Application> application = applicationRepo.findById(UUID.fromString(applicationId));

        if (application.isEmpty()) {
            logger.error("refreshApplicationToken() cannot find the application by applicationId: {}", applicationId);
            throw new IllegalArgumentException("Cannot find application by the given applicationId: " + applicationId);
        }

        String newApplicationToken = generateApplicationToken(application.orElse(null));
        try {
            application.get().setToken(
                    newApplicationToken
            );

            this.applicationRepo.save(application.get());
        } catch (Exception e) {
            logger.error("", e);
        }

        return newApplicationToken;
    }

    private void checkAssociation(List<Application> applications) {
        for (Application application : applications) {
            if (application.getPrivileges() != null) {
                Set<Privilege> privileges = new HashSet<>();
                application.getPrivileges().forEach(p -> {
                    Optional<Privilege> optionalPrivilege = privilegeRepo.findById(p.getUuid());
                    if (optionalPrivilege.isPresent()) {
                        Privilege privilege = optionalPrivilege.get();
                        privilege.setApplication(application);
                        privileges.add(privilege);
                    } else {
                        logger.error("Didn't find privilege by uuid: {}", p.getUuid());
                    }
                });
                application.setPrivileges(privileges);

            }
        }
    }

    public String generateApplicationToken(Application application) {
        if (application == null || application.getUuid() == null) {
            logger.error("generateApplicationToken() application is null or uuid is missing to generate the application token");
            throw new NullPointerException("Cannot generate application token, please contact admin");
        }

        return JWTUtil.createJwtToken(
                null, null,
                new HashMap<>(
                        Map.of(
                                "user_id", AuthNaming.PSAMA_APPLICATION_TOKEN_PREFIX + "|" + application.getName()
                        )
                ),
                AuthNaming.PSAMA_APPLICATION_TOKEN_PREFIX + "|" + application.getUuid().toString(), 365L * 1000 * 60 * 60 * 24);
    }

}

