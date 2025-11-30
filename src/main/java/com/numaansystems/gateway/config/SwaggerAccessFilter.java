package com.numaansystems.gateway.config;

import jakarta.servlet.*;
import jakarta.servlet.http. HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org. slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;

/**
 * Servlet filter to restrict Swagger UI access to specific configured users.
 * 
 * <p>This filter checks if the authenticated user's email is in the
 * allowed-users list before granting access to Swagger endpoints.</p>
 * 
 * <h2>Configuration</h2>
 * <p>Configure allowed users in application.yml:</p>
 * <pre>
 * gateway:
 *   swagger:
 *     enabled: true
 *     allowed-users:
 *       - admin@numaansystems.com
 *       - developer@numaansystems.com
 * </pre>
 * 
 * <h2>Protected Endpoints</h2>
 * <ul>
 *   <li>/swagger-ui/** - Swagger UI interface</li>
 *   <li>/api-docs/** - OpenAPI documentation</li>
 *   <li>/v3/api-docs/** - OpenAPI v3 specification</li>
 * </ul>
 * 
 * @author Numaan Systems
 * @version 0.1.0
 */
@Component
public class SwaggerAccessFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(SwaggerAccessFilter.class);

    @Value("${gateway.swagger. enabled:true}")
    private boolean swaggerEnabled;

    @Value("${gateway.swagger.allowed-users:}")
    private List<String> allowedUsers;

    /**
     * Filters requests to Swagger endpoints based on user authorization.
     * 
     * <p>Checks if:</p>
     * <ol>
     *   <li>Swagger is enabled in configuration</li>
     *   <li>User is authenticated</li>
     *   <li>User's email is in the allowed-users list</li>
     * </ol>
     * 
     * @param request the servlet request
     * @param response the servlet response
     * @param chain the filter chain
     * @throws IOException if I/O error occurs
     * @throws ServletException if servlet error occurs
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String requestURI = httpRequest.getRequestURI();

        // Check if request is for Swagger endpoints
        if (requestURI. contains("/swagger-ui") || requestURI.contains("/api-docs") || requestURI. contains("/v3/api-docs")) {
            
            if (! swaggerEnabled) {
                logger.warn("Swagger access denied: Swagger is disabled");
                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Swagger UI is disabled");
                return;
            }

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated()) {
                logger.warn("Swagger access denied: User not authenticated");
                httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication required for Swagger UI");
                return;
            }

            // Extract user email from OAuth2User
            String userEmail = null;
            if (authentication. getPrincipal() instanceof OAuth2User oauth2User) {
                userEmail = oauth2User.getAttribute("email");
                if (userEmail == null) {
                    userEmail = oauth2User.getAttribute("preferred_username");
                }
            }

            // Check if user is in allowed list
            if (userEmail == null || !allowedUsers.contains(userEmail)) {
                logger.warn("Swagger access denied for user: {}", userEmail);
                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Access to Swagger UI is restricted");
                return;
            }

            logger.info("Swagger access granted to user: {}", userEmail);
        }

        chain.doFilter(request, response);
    }
}
