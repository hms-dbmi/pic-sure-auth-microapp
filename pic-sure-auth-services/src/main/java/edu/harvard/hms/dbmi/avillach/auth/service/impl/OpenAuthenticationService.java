package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.entity.Role;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.service.RoleService;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class OpenAuthenticationService {

    private final Logger logger = LoggerFactory.getLogger(OpenAuthenticationService.class);

    private final UserService userService;
    private final RoleService roleRepository;

    @Autowired
    public OpenAuthenticationService(UserService userService, RoleService roleRepository) {
        this.userService = userService;
        this.roleRepository = roleRepository;
    }


    public Map<String, String> authenticate(Map<String, String> authRequest) {
        String userUUID = authRequest.get("UUID");
        User current_user = null;

        // Try to get the user by UUID
        if (StringUtils.isNotBlank(userUUID)) {
            try {
                current_user = userService.findUserByUUID(userUUID);
            } catch (IllegalArgumentException e) {
                logger.error("Invalid UUID: {}", userUUID);
            }
        }

        // If we can't find the user by UUID, create a new one
        if (current_user == null) {
            Role openAccessRole = roleRepository.getRoleByName(FENCEAuthenticationService.fence_open_access_role_name);
            current_user = userService.createOpenAccessUser(openAccessRole);

            //clear some cache entries if we register a new login
            // I don't see a clear need to caching here.
            // TODO: Need to implement some form of caching
//            AuthorizationService.clearCache(current_user);
//            UserService.clearCache(current_user);
        }

        HashMap<String, Object> claims = new HashMap<>();
        claims.put("sub", current_user.getSubject());
        claims.put("email", current_user.getUuid() + "@open_access.com");
        claims.put("uuid", current_user.getUuid().toString());
        HashMap<String, String> responseMap = userService.getUserProfileResponse(claims);

        logger.info("LOGIN SUCCESS ___ {}:{} ___ Authorization will expire at  ___ {}___", current_user.getEmail(), current_user.getUuid().toString(), responseMap.get("expirationDate"));

        return responseMap;
    }
}
