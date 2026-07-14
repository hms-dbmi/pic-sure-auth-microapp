package edu.harvard.hms.dbmi.avillach.auth.config;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.CustomUserDetailService;

import java.time.Instant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.interceptor.KeyGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;

@Configuration
@EnableCaching
public class ApplicationConfig {

    private final CustomUserDetailService customUserDetailService;

    @Autowired
    public ApplicationConfig(CustomUserDetailService customUserDetailService) {
        this.customUserDetailService = customUserDetailService;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(customUserDetailService);
        return provider;
    }

    @Bean("customKeyGenerator")
    public KeyGenerator generator() {
        return new CustomKeyGenerator();
    }

    @Bean
    public ObjectMapper objectMapper() {
        // this bean replaces Boot's auto-configured mapper, which would otherwise register
        // java.time support itself; without JavaTimeModule any Instant field fails (de)serialization.
        // Instant renders as an ISO-8601 string; the shape is overridden per-type rather than via
        // WRITE_DATES_AS_TIMESTAMPS so legacy java.util.Date fields keep their epoch-millis rendering.
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        objectMapper.configOverride(Instant.class).setFormat(JsonFormat.Value.forShape(JsonFormat.Shape.STRING));
        return objectMapper;
    }
}
