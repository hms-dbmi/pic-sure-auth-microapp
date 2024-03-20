package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.entity.TermsOfService;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.repository.TermsOfServiceRepository;
import edu.harvard.hms.dbmi.avillach.auth.repository.UserRepository;
import edu.harvard.hms.dbmi.avillach.auth.rest.TermsOfSerivceController;
import edu.harvard.hms.dbmi.avillach.auth.rest.UserController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.persistence.NoResultException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * <p>Provides business logic for the TermsOfService endpoint.</p>>
 *
 * @see TermsOfSerivceController
 */
@Service
public class TOSService {

    private final static Logger logger = LoggerFactory.getLogger(TOSService.class);

    @Value("${application.tos.enabled}")
    private boolean isToSEnabled;

    private final TermsOfServiceRepository termsOfServiceRepo;

    private final UserRepository userRepo;

    private final UserController userController; // TODO: This isn't a service its a controller. Why are we doing this?

    @Autowired
    public TOSService(TermsOfServiceRepository termsOfServiceRepo, UserRepository userRepo, UserController userController) {
        this.termsOfServiceRepo = termsOfServiceRepo;
        this.userRepo = userRepo;
        this.userController = userController;
    }


    public boolean hasUserAcceptedLatest(String userId){
        // If TOS is not enabled, then the user has accepted it
        if (!isToSEnabled){
            return true;
        }

        // If there is no TOS, then the user has accepted it
        if (getLatest() == null) {
            return true;
        }

        logger.info("Checking Terms Of Service acceptance for user with id " + userId);
        return userRepo.checkAgainstTOSDate(userId);
    }

    public TermsOfService updateTermsOfService(String html){
        TermsOfService updatedTOS = new TermsOfService();
        updatedTOS.setContent(html);
        termsOfServiceRepo.persist(updatedTOS);
        return termsOfServiceRepo.getLatest();
    }

    public String getLatest(){
        try {
            return termsOfServiceRepo.getLatest().getContent();
        } catch (NoResultException e){
            logger.info("Terms Of Service disabled: No Terms of Service found in database");
            return null;
        }
    }

    public void acceptTermsOfService(String userId){
        logger.info("User " + userId + " accepting TOS");
        User user = userRepo.findBySubject(userId);
        if (user == null){
            throw new RuntimeException("User does not exist");
        }
        user.setAcceptedTOS(new Date());
        List<User> users = Arrays.asList(user);
        Date tosDate = termsOfServiceRepo.getLatest().getDateUpdated();
        userController.updateUser(users);
        logger.info("TOS_LOG : User " + (!StringUtils.isEmpty(user.getEmail()) ? user.getEmail() : user.getGeneralMetadata()) + " accepted the Terms of Service dated " + tosDate.toString());
    }

}
