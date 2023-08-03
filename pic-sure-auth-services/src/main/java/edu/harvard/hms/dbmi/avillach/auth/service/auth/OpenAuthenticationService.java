package edu.harvard.hms.dbmi.avillach.auth.service.auth;

import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.UserRepository;
import edu.harvard.hms.dbmi.avillach.auth.rest.UserService;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class OpenAuthenticationService {

    private final Logger logger = LoggerFactory.getLogger(OpenAuthenticationService.class);

    @Inject
    private UserRepository userRepository;

    @Inject
    AuthUtils authUtil;

    @Inject
    private FENCEAuthenticationService fenceAuthenticationService;

    public Response authenticate(Map<String, String> authRequest) {
        String userUUID = authRequest.get("UUID");
        User current_user = null;

        // Try to get the user by UUID
        if (StringUtils.isNotBlank(userUUID)) {
            UUID uuid = UUID.fromString(userUUID);
            current_user = userRepository.findByUUID(uuid);
        }

        // If we can't find the user by UUID, create a new one
        if (current_user == null) {
            current_user = userRepository.createOpenAccessUser();

            //clear some cache entries if we register a new login
            AuthorizationService.clearCache(current_user);
            UserService.clearCache(current_user);

            setDefaultUserRoles(current_user);
        }

        HashMap<String, Object> claims = new HashMap<>();
        claims.put("sub", current_user.getSubject());
        claims.put("email", current_user.getUuid() + "@open_access.com");
        claims.put("uuid", current_user.getUuid().toString());
        HashMap<String, String> responseMap = authUtil.getUserProfileResponse(claims);

        logger.info("LOGIN SUCCESS ___ " + current_user.getEmail() + ":" + current_user.getUuid().toString() + " ___ Authorization will expire at  ___ " + responseMap.get("expirationDate") + "___");

        return PICSUREResponse.success(responseMap);
    }

    private void setDefaultUserRoles(User current_user) {
        fenceAuthenticationService.upsertRole(current_user, "FENCE_PRIV_OPEN_ACCESS", null);
        fenceAuthenticationService.upsertRole(current_user, "FENCE_PRIV_DICTIONARY", null);
        userRepository.merge(current_user);
    }
}
