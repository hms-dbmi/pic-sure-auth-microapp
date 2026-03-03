package edu.harvard.hms.dbmi.avillach.auth.config;

import edu.harvard.dbmi.avillach.logging.LoggingClient;
import edu.harvard.dbmi.avillach.logging.LoggingClientFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LoggingConfig {

    @Bean
    public LoggingClient loggingClient() {
        return LoggingClientFactory.create("auth");
    }
}
