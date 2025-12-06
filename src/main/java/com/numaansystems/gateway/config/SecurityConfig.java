package com.numaansystems.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;

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
    private final CorsConfigurationSource corsConfigurationSource;

    /**
     * Constructor injection of custom authentication success handler and Swagger filter.
     * 
     * @param successHandler handles OAuth2 authentication success
     * @param swaggerAccessFilter filters Swagger access by user
     * @param corsConfigurationSource CORS configuration
     */
    public SecurityConfig(CustomAuthenticationSuccessHandler successHandler,
                         SwaggerAccessFilter swaggerAccessFilter,
                         CorsConfigurationSource corsConfigurationSource) {
        this.successHandler = successHandler;
        this.swaggerAccessFilter = swaggerAccessFilter;
        this.corsConfigurationSource = corsConfigurationSource;
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
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/actuator/**", "/error", "/auth/**").permitAll()
                // Allow /app/** without gateway authentication - legacy app handles its own auth
                // Note: In production, consider adding rate limiting or additional validation
                .requestMatchers("/app/**").permitAll()
                .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/api-docs/**", "/v3/api-docs/**").authenticated()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .successHandler(successHandler)
            )
            .addFilterAfter(swaggerAccessFilter, UsernamePasswordAuthenticationFilter.class)
            .csrf(csrf -> csrf.disable());

        return http.build();
    }


}
