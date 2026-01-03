package com.example.legacyapp.filter;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.UUID;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Azure AD OAuth2 Filter - Java 6 Compatible
 * 
 * Direct Azure AD OAuth2 integration filter for Spring Framework 3
 * Checks if user is authenticated and initiates OAuth2 authorization flow.
 * The actual callback handling is done by AzureADCallbackFilter.
 * 
 * Configuration required in web.xml or Spring configuration:
 * - azureAd.clientId
 * - azureAd.tenantId
 * - azureAd.redirectUri
 * - azureAd.scope (optional, defaults to "openid profile email")
 * 
 * @author Generated for Legacy App Migration
 * @version 1.0
 * @since 2025-12-23
 */
public class AzureADOAuth2Filter implements Filter {
    
    // Configuration parameters
    private String clientId;
    private String tenantId;
    private String redirectUri;
    private String scope = "openid profile email";
    
    // Azure AD endpoints
    private String authorizationEndpoint;
    
    // Session attribute keys
    private static final String SESSION_STATE_KEY = "oauth2_state";
    private static final String SESSION_AUTHENTICATED_KEY = "authenticated";
    private static final String SESSION_USER_PRINCIPAL_KEY = "userPrincipal";
    private static final String SESSION_ACCESS_TOKEN_KEY = "oauth2_access_token";
    private static final String SESSION_ID_TOKEN_KEY = "oauth2_id_token";
    private static final String SESSION_USER_INFO_KEY = "oauth2_user_info";
    private static final String SESSION_TOKEN_EXPIRY_KEY = "oauth2_token_expiry";
    
    // Excluded paths (no authentication required)
    private static final String[] EXCLUDED_PATHS = {
        "/health", "/actuator", "/public", "/static", "/css", "/js", "/images",
        "/login/oauth2/code/azure"  // OAuth2 callback path handled by AzureADCallbackFilter
    };
    
    /**
     * Initialize filter with configuration parameters
     */
    public void init(FilterConfig filterConfig) throws ServletException {
        // Read configuration from filter init parameters
        clientId = getConfigParameter(filterConfig, "azureAd.clientId");
        tenantId = getConfigParameter(filterConfig, "azureAd.tenantId");
        redirectUri = getConfigParameter(filterConfig, "azureAd.redirectUri");
        
        String scopeParam = filterConfig.getInitParameter("azureAd.scope");
        if (scopeParam != null && scopeParam.length() > 0) {
            scope = scopeParam;
        }
        
        // Validate required configuration
        if (clientId == null || tenantId == null || redirectUri == null) {
            throw new ServletException("Missing required Azure AD configuration parameters. " +
                "Required: azureAd.clientId, azureAd.tenantId, azureAd.redirectUri");
        }
        
        // Construct Azure AD endpoints
        authorizationEndpoint = String.format(
            "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tenantId);
        
        System.out.println("AzureADOAuth2Filter initialized for tenant: " + tenantId);
    }
    
    /**
     * Main filter logic - handles OAuth2 flow
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        HttpSession session = httpRequest.getSession(true);
        
        String requestPath = httpRequest.getRequestURI();
        String contextPath = httpRequest.getContextPath();
        String path = requestPath.substring(contextPath.length());
        
        // Skip authentication for excluded paths
        if (isExcludedPath(path)) {
            chain.doFilter(request, response);
            return;
        }
        
        // Check if user is already authenticated
        if (isAuthenticated(httpRequest, session)) {
            // Refresh token if expired
            if (isTokenExpired(session)) {
                refreshAccessToken(session);
            }
            chain.doFilter(request, response);
            return;
        }
        
        // Initiate OAuth2 authorization flow
        initiateAuthorizationFlow(httpRequest, httpResponse, session);
    }
    
    /**
     * Clean up resources
     */
    public void destroy() {
        // Clean up any resources if needed
        System.out.println("AzureADOAuth2Filter destroyed");
    }
    
    /**
     * Check if path should be excluded from authentication
     */
    private boolean isExcludedPath(String path) {
        for (int i = 0; i < EXCLUDED_PATHS.length; i++) {
            if (path.startsWith(EXCLUDED_PATHS[i])) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check if user is authenticated (has valid session set by AzureADCallbackFilter)
     */
    private boolean isAuthenticated(HttpServletRequest request, HttpSession session) {
        // Check session for authenticated flag (set by AzureADCallbackFilter)
        Boolean authenticated = (Boolean) session.getAttribute(SESSION_AUTHENTICATED_KEY);
        if (authenticated != null && authenticated.booleanValue()) {
            return true;
        }
        
        // Fallback: check for access token (legacy key)
        String accessToken = (String) session.getAttribute(SESSION_ACCESS_TOKEN_KEY);
        if (accessToken != null && accessToken.length() > 0) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if access token has expired
     */
    private boolean isTokenExpired(HttpSession session) {
        Long expiryTime = (Long) session.getAttribute(SESSION_TOKEN_EXPIRY_KEY);
        if (expiryTime == null) {
            return true;
        }
        return System.currentTimeMillis() >= expiryTime.longValue();
    }
    
    /**
     * Initiate OAuth2 authorization flow by redirecting to Azure AD
     */
    private void initiateAuthorizationFlow(HttpServletRequest request, 
                                          HttpServletResponse response,
                                          HttpSession session) throws IOException {
        // Generate and store state parameter for CSRF protection
        String state = UUID.randomUUID().toString();
        session.setAttribute(SESSION_STATE_KEY, state);
        
        // Build authorization URL
        StringBuilder authUrl = new StringBuilder(authorizationEndpoint);
        authUrl.append("?client_id=").append(urlEncode(clientId));
        authUrl.append("&response_type=code");
        authUrl.append("&redirect_uri=").append(urlEncode(redirectUri));
        authUrl.append("&response_mode=query");
        authUrl.append("&scope=").append(urlEncode(scope));
        authUrl.append("&state=").append(urlEncode(state));
        
        // Redirect to Azure AD authorization endpoint
        response.sendRedirect(authUrl.toString());
    }
    
    /**
     * Refresh access token (simplified - would need refresh token support)
     */
    private void refreshAccessToken(HttpSession session) {
        // In a production implementation, this would use the refresh token
        // For now, we'll just clear the session and force re-authentication
        session.removeAttribute(SESSION_ACCESS_TOKEN_KEY);
        session.removeAttribute(SESSION_ID_TOKEN_KEY);
        session.removeAttribute(SESSION_USER_INFO_KEY);
        session.removeAttribute(SESSION_TOKEN_EXPIRY_KEY);
    }
    
    /**
     * Get configuration parameter from filter config
     */
    private String getConfigParameter(FilterConfig filterConfig, String paramName) {
        String value = filterConfig.getInitParameter(paramName);
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
}
