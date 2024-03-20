package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

@Service
public class UserService {

    private final Logger logger = Logger.getLogger(UserService.class.getName());

    private final TOSService tosService;

    @Autowired
    public UserService(TOSService tosService) {
        this.tosService = tosService;
    }

    public HashMap<String, String> getUserProfileResponse(Map<String, Object> claims) {
        logger.info("getUserProfileResponse() starting...");

        HashMap<String, String> responseMap = new HashMap<String, String>();
        logger.info("getUserProfileResponse() initialized map");

        logger.info("getUserProfileResponse() using claims:" + claims.toString());

        String token = JWTUtil.createJwtToken(
                JAXRSConfiguration.clientSecret,
                "whatever",
                "edu.harvard.hms.dbmi.psama",
                claims,
                claims.get("sub").toString(),
                JAXRSConfiguration.tokenExpirationTime
        );
        logger.info("getUserProfileResponse() PSAMA JWT token has been generated. Token:" + token);
        responseMap.put("token", token);

        logger.info("getUserProfileResponse() .usedId field is set");
        responseMap.put("userId", claims.get("sub").toString());

        logger.info("getUserProfileResponse() .email field is set");
        responseMap.put("email", claims.get("email").toString());

        logger.info("getUserProfileResponse() acceptedTOS is set");

        boolean acceptedTOS = tosService.hasUserAcceptedLatest(claims.get("sub").toString());

        responseMap.put("acceptedTOS", "" + acceptedTOS);

        logger.info("getUserProfileResponse() expirationDate is set");
        Date expirationDate = new Date(Calendar.getInstance().getTimeInMillis() + JAXRSConfiguration.tokenExpirationTime);
        responseMap.put("expirationDate", ZonedDateTime.ofInstant(expirationDate.toInstant(), ZoneOffset.UTC).toString());

        logger.info("getUserProfileResponse() finished");
        return responseMap;
    }

}
