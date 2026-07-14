package edu.harvard.hms.dbmi.avillach.auth.service.impl.captcha;

import edu.harvard.hms.dbmi.avillach.auth.service.CaptchaVerifier;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Service
@ConditionalOnProperty(name = "captcha.provider", havingValue = "disabled", matchIfMissing = true)
public class DisabledCaptchaVerifier implements CaptchaVerifier {

    private static final Logger logger = LoggerFactory.getLogger(DisabledCaptchaVerifier.class);

    @PostConstruct
    public void warnDisabled() {
        logger.warn("CAPTCHA verification is DISABLED - API key generation is not gated against automated key farming");
    }

    @Override
    public boolean verify(String captchaToken, String remoteIp) {
        return true;
    }
}
