package com.innoboard.authservice.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

@Configuration
public class UserClientConfig {

    @Bean
    public RestClient userRestClient(@Value("${app.services.user-url}") String userUrl) {
        return RestClient.builder().baseUrl(userUrl).build();
    }
}
