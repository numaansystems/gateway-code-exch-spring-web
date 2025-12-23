package com.numaansystems.gateway.config;

import org.springframework.context.annotation. Bean;
import org.springframework. context.annotation.Configuration;
import org.springframework.security.config. annotation.web.builders.HttpSecurity;
import org.springframework. security.config.annotation.web. configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web. authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors. UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * Spring Security Configuration with CORS and Authentication
 * 
 * @version 0.2.0 - Fixed: Restored authentication requirements with CORS support
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomAuthenticationSuccessHandler successHandler;
    private final SwaggerAccessFilter swaggerAccessFilter;

    public SecurityConfig(CustomAuthenticationSuccessHandler successHandler,
                         SwaggerAccessFilter swaggerAccessFilter) {
        this.successHandler = successHandler;
        this. swaggerAccessFilter = swaggerAccessFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Enable CORS
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            // Configure authorization - FIXED: Require authentication except for public endpoints
            .authorizeHttpRequests(authz -> authz
                // Public endpoints
                .requestMatchers("/actuator/**", "/error", "/auth/**", "/test/**").permitAll()
                .requestMatchers("/oauth2/**", "/login/**").permitAll()
                .requestMatchers("/myapp/**").permitAll()
                
                // Protected endpoints
                .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/api-docs/**", "/v3/api-docs/**").authenticated()
                
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            
            // OAuth2 login with custom handler
            .oauth2Login(oauth2 -> oauth2
                . successHandler(successHandler)
            )
            
            // Swagger access filter
            .addFilterAfter(swaggerAccessFilter, UsernamePasswordAuthenticationFilter.class)
            
            // Disable CSRF
            .csrf(csrf -> csrf.disable());

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(
            "http://localhost:8080",
            "http://localhost:8081",
            "http://qa-server: 8080",
            "https://app.company.com",
            "https://legacy. company.com"
        ));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"));
        configuration. setAllowedHeaders(Arrays. asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        configuration.setExposedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With"));
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
