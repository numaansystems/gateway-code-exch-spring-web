package com.numaansystems.gateway.controller;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context. annotation.Bean;
import org. springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework. security.web.SecurityFilterChain;

/**
 * Test security configuration that permits all requests.
 * 
 * <p>This configuration is used in @WebMvcTest to bypass security
 * for controller unit tests, allowing focus on controller logic.</p>
 */
@TestConfiguration
@EnableWebSecurity
public class TestSecurityConfig {

    /**
     * Configures a security filter chain that permits all requests.
     * 
     * @param http the HttpSecurity to configure
     * @return the configured SecurityFilterChain
     * @throws Exception if configuration fails
     */
    @Bean
    public SecurityFilterChain testSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                .anyRequest().permitAll()
            )
            .csrf(csrf -> csrf.disable());
        
        return http.build();
    }
}
