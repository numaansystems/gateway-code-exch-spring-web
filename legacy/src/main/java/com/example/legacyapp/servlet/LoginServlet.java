package com.example.legacyapp.servlet;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.math.BigInteger;

/**
 * Servlet to initiate Azure AD OAuth2 login flow.
 * Java 6 compatible implementation.
 * 
 * <p>Generates a random state parameter for CSRF protection and redirects
 * to Azure AD authorization endpoint with prompt=select_account to force
 * account selection and prevent automatic sign-in.</p>
 * 
 * @author Legacy App Integration
 * @version 1.0
 */
public class LoginServlet extends HttpServlet {
    
    private String clientId;
    private String tenantId;
    private String redirectUri;
    private String scope = "openid profile email";
    
    private String authorizationEndpoint;
    
    private static final String SESSION_STATE_KEY = "oauth2_state";
    
    /**
     * Initialize servlet with configuration parameters
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        
        // Read configuration from servlet init parameters
        clientId = getConfigParameter(config, "azureAd.clientId");
        tenantId = getConfigParameter(config, "azureAd.tenantId");
        redirectUri = getConfigParameter(config, "azureAd.redirectUri");
        
        String scopeParam = config.getInitParameter("azureAd.scope");
        if (scopeParam != null && scopeParam.length() > 0) {
            scope = scopeParam;
        }
        
        // Validate required configuration
        if (clientId == null || tenantId == null || redirectUri == null) {
            throw new ServletException("Missing required Azure AD configuration parameters. " +
                "Required: azureAd.clientId, azureAd.tenantId, azureAd.redirectUri");
        }
        
        // Validate tenant ID format (UUID or domain)
        if (!isValidTenantId(tenantId)) {
            throw new ServletException("Invalid Azure AD tenant ID format: " + tenantId);
        }
        
        // Construct Azure AD authorization endpoint
        authorizationEndpoint = String.format(
            "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tenantId);
        
        System.out.println("LoginServlet initialized for tenant: " + tenantId);
    }
    
    /**
     * Handle GET request - initiate OAuth2 login flow
     */
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        System.out.println("LoginServlet: Initiating Azure AD login");
        
        HttpSession session = request.getSession(true);
        
        // Generate random state for CSRF protection
        String state = generateState();
        session.setAttribute(SESSION_STATE_KEY, state);
        
        // Build authorization URL with prompt=select_account
        StringBuilder authUrl = new StringBuilder();
        authUrl.append(authorizationEndpoint);
        authUrl.append("?client_id=").append(urlEncode(clientId));
        authUrl.append("&response_type=code");
        authUrl.append("&redirect_uri=").append(urlEncode(redirectUri));
        authUrl.append("&scope=").append(urlEncode(scope));
        authUrl.append("&state=").append(urlEncode(state));
        authUrl.append("&prompt=select_account"); // Force account selection
        
        String authorizationUrl = authUrl.toString();
        System.out.println("LoginServlet: Redirecting to Azure AD: " + authorizationUrl);
        
        response.sendRedirect(authorizationUrl);
    }
    
    /**
     * Generate random state parameter for CSRF protection
     */
    private String generateState() {
        SecureRandom random = new SecureRandom();
        return new BigInteger(130, random).toString(32);
    }
    
    /**
     * Get configuration parameter from servlet config or system properties
     */
    private String getConfigParameter(ServletConfig config, String paramName) {
        String value = config.getInitParameter(paramName);
        if (value == null || value.trim().length() == 0) {
            // Try system property as fallback
            value = System.getProperty(paramName);
        }
        return value;
    }
    
    /**
     * URL encode string (Java 6 compatible)
     */
    private String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported", e);
        }
    }
    
    /**
     * Validate tenant ID format (UUID or domain name)
     */
    private boolean isValidTenantId(String tenantId) {
        if (tenantId == null || tenantId.length() == 0) {
            return false;
        }
        
        // Check for UUID format (8-4-4-4-12 hex digits)
        if (tenantId.matches("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")) {
            return true;
        }
        
        // Check for domain name format (common, organizations, consumers, or custom domain)
        if (tenantId.matches("^[a-zA-Z0-9][a-zA-Z0-9-\\.]*[a-zA-Z0-9]$")) {
            return true;
        }
        
        return false;
    }
}
