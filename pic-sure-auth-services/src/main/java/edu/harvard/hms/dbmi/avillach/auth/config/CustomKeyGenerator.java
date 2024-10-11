package edu.harvard.hms.dbmi.avillach.auth.config;

import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.interceptor.KeyGenerator;

import java.lang.reflect.Method;

public class CustomKeyGenerator implements KeyGenerator {

    private final Logger logger = LoggerFactory.getLogger(CustomKeyGenerator.class);

    @Override
    public Object generate(Object target, Method method, Object... params) {
        String key = null;
        for (Object param : params) {
            if (param instanceof User user) {
                key = user.getSubject();
            }

            if (param instanceof String userSubject) {
                key = userSubject;
            }
        }

        if (key != null) {
            logger.info("Generated cache key: {}", key);
            return key;
        }

        throw new IllegalArgumentException("No valid params found. Cannot generate cache key");
    }
}
