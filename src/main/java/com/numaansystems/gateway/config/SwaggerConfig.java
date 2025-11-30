package com. numaansystems.gateway.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger. v3.oas.models. info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Swagger/OpenAPI configuration for API documentation. 
 * 
 * <p>Provides interactive API documentation via Swagger UI.  
 * Access is restricted to configured users only through Spring Security.</p>
 * 
 * <h2>Access</h2>
 * <ul>
 *   <li>Swagger UI: /gateway/swagger-ui. html</li>
 *   <li>OpenAPI JSON: /gateway/api-docs</li>
 * </ul>
 * 
 * <h2>Security</h2>
 * <p>Access is controlled by {@link SwaggerAccessFilter} which checks if the
 * authenticated user's email is in the gateway. swagger.allowed-users list.</p>
 * 
 * @author Numaan Systems
 * @version 0.1.0
 */
@Configuration
public class SwaggerConfig {

    /**
     * Configures OpenAPI documentation metadata.
     * 
     * @return OpenAPI configuration with title, description, version, and contact info
     */
    @Bean
    public OpenAPI gatewayOpenAPI() {
        return new OpenAPI()
            . info(new Info()
                . title("Azure AD Gateway API")
                .description("OAuth2 authentication gateway for legacy applications integrating with Azure AD")
                . version("0.1.0")
                .contact(new Contact()
                    .name("Numaan Systems")
                    .email("support@numaansystems.com"))
                .license(new License()
                    .name("MIT License")
                    .url("https://opensource.org/licenses/MIT")));
    }
}
