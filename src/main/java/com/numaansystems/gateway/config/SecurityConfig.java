package com. numaansystems.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework. security.web.SecurityFilterChain;
import org.springframework.security.web. authentication.UsernamePasswordAuthenticationFilter;

/**
 * Spring Security configuration for Azure AD OAuth2 authentication.
 * 
 * <p>This configuration sets up servlet-based (NOT reactive) Spring Security
 * with OAuth2 login using Azure AD as the identity provider.</p>
 * 
 * <h2>Security Configuration</h2>
 * <ul>
 *   <li>Public endpoints: /actuator/**, /error, /auth/**</li>
 *   <li>Protected endpoints: /swagger-ui/**, /api-docs/** (requires authentication + whitelist)</li>
 *   <li>All other endpoints require authentication</li>
 *   <li>OAuth2 login with custom success handler</li>
 *   <li>CSRF disabled (stateless token exchange pattern)</li>
 * </ul>
 * 
 * <h2>Session Management</h2>
 * <p>Session configuration is defined in application.yml:</p>
 * <ul>
 *   <li>HTTP-only cookies (not accessible to JavaScript)</li>
 *   <li>Secure flag (HTTPS only in production)</li>
 *   <li>SameSite=Lax (CSRF protection)</li>
 * </ul>
 * 
 * @author Numaan Systems
 * @version 0.1.0
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomAuthenticationSuccessHandler successHandler;
    private final SwaggerAccessFilter swaggerAccessFilter;

    /**
     * Constructor injection of custom authentication success handler and Swagger filter.
     * 
     * @param successHandler handles OAuth2 authentication success
     * @param swaggerAccessFilter filters Swagger access by user
     */
    public SecurityConfig(CustomAuthenticationSuccessHandler successHandler,
                         SwaggerAccessFilter swaggerAccessFilter) {
        this.successHandler = successHandler;
        this. swaggerAccessFilter = swaggerAccessFilter;
    }

    /**
     * Configures the security filter chain for servlet-based Spring Security.
     * 
     * <p>This method defines authorization rules and OAuth2 login configuration. 
     * Note: This uses HttpSecurity (servlet) NOT ServerHttpSecurity (reactive).</p>
     * 
     * @param http the HttpSecurity to configure
     * @return the configured SecurityFilterChain
     * @throws Exception if configuration fails
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Configure authorization
            .authorizeHttpRequests(authz -> authz
                // Public endpoints - no authentication required
                .requestMatchers("/actuator/**", "/error", "/auth/**", "/test/**").permitAll()
                // Proxied legacy app endpoints - no authentication required (legacy app handles auth)
                .requestMatchers("/myapp/**").permitAll()
                // Swagger endpoints - authentication required (filtered by SwaggerAccessFilter)
                .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/api-docs/**", "/v3/api-docs/**").authenticated()
                // All other endpoints require authentication
                .anyRequest().authenticated()
            )
            // Configure OAuth2 login
            .oauth2Login(oauth2 -> oauth2
                // Custom success handler for token exchange
                .successHandler(successHandler)
            )
            // Add Swagger access filter
            .addFilterAfter(swaggerAccessFilter, UsernamePasswordAuthenticationFilter.class)
            // Disable CSRF for stateless token exchange pattern
            .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
