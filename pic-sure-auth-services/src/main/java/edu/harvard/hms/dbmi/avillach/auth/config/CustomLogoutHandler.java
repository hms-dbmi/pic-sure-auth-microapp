package edu.harvard.hms.dbmi.avillach.auth.config;

import edu.harvard.hms.dbmi.avillach.auth.model.CustomUserDetails;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.AccessRuleService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.SessionService;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomLogoutHandler implements LogoutHandler {

    private final Logger logger = LoggerFactory.getLogger(CustomLogoutHandler.class);
    private final SessionService sessionService;
    private final UserService userService;
    private final AccessRuleService accessRuleService;

    public CustomLogoutHandler(SessionService sessionService, UserService userService, AccessRuleService accessRuleService) {
        this.sessionService = sessionService;
        this.userService = userService;
        this.accessRuleService = accessRuleService;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Object principal = authentication.getPrincipal();

        if (!(principal instanceof CustomUserDetails customUserDetails)) {
            logger.error("logout() Principal is not an instance of User.");
        } else {
            logger.info("logout() Logging out User: {}", customUserDetails.getUsername());
            this.sessionService.endSession(customUserDetails.getUsername());
            this.userService.evictFromCache(customUserDetails.getUsername());
            this.accessRuleService.evictFromCache(customUserDetails.getUsername());
        }
    }
}

