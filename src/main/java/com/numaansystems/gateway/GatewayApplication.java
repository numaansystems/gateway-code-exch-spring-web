package com.numaansystems.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Azure AD Gateway Application
 * 
 * <p>This Spring Boot application provides an OAuth2 authentication gateway
 * for legacy applications that need to integrate with Azure AD (Microsoft Entra ID)
 * but cannot natively support modern OAuth2/OIDC flows. </p>
 * 
 * <h2>Purpose</h2>
 * <ul>
 *   <li>Acts as authentication proxy between legacy apps and Azure AD</li>
 *   <li>Handles OAuth2 authorization code flow with Azure AD</li>
 *   <li>Provides simple REST endpoints for legacy app integration</li>
 *   <li>Issues short-lived, single-use exchange tokens</li>
 *   <li>Supports cross-domain authentication scenarios</li>
 *   <li>Merges authorities from Azure AD and optional database</li>
 * </ul>
 * 
 * <h2>Architecture</h2>
 * <p>The gateway uses a token exchange pattern:</p>
 * <ol>
 *   <li>Legacy app redirects user to /auth/initiate with returnUrl</li>
 *   <li>Gateway initiates OAuth2 flow with Azure AD</li>
 *   <li>User authenticates with Azure AD (including MFA if enabled)</li>
 *   <li>Gateway receives OAuth2 callback and creates exchange token</li>
 *   <li>User redirected back to legacy app with exchange token</li>
 *   <li>Legacy app validates token via backend API call</li>
 *   <li>Gateway returns user details and authorities</li>
 *   <li>Legacy app creates its own session</li>
 * </ol>
 * 
 * <h2>Security Features</h2>
 * <ul>
 *   <li>HTTP-only, secure session cookies</li>
 *   <li>Single-use exchange tokens (consumed on validation)</li>
 *   <li>Short token lifetime (2 minutes, accommodates MFA)</li>
 *   <li>Domain whitelist for redirect validation</li>
 *   <li>Backend-to-backend token validation (no CORS issues)</li>
 *   <li>No sensitive data exposed in URLs</li>
 * </ul>
 * 
 * @author Numaan Systems
 * @version 0.1.0
 * @since 2025-11-30
 */
@SpringBootApplication
public class GatewayApplication {

    /**
     * Main entry point for the Azure AD Gateway application.
     * 
     * @param args command-line arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
