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
 * Handles authentication checks and initiates authorization flow.
 * Token exchange is handled by AzureADCallbackFilter.
 * 
 * Configuration required in web.xml or Spring configuration:
 * - azureAd.clientId
 * - azureAd.tenantId
 * - azureAd.redirectUri
 * - azureAd.scope (optional, defaults to "openid profile email")
 * 
 * @author Generated for Legacy App Migration
 * @version 2.0
 * @since 2025-12-29
 */
public class AzureADOAuth2Filter implements Filter {
    
    // Configuration parameters
    private String clientId;
    private String tenantId;
    private String redirectUri;
    private String scope = "openid profile email";
    private String callbackPath = "/login/oauth2/code/azure";
    
    // Azure AD endpoints
    private String authorizationEndpoint;
    
    // Session attribute keys
    private static final String SESSION_STATE_KEY = "oauth2_state";
    private static final String SESSION_ACCESS_TOKEN_KEY = "oauth2_access_token";
    private static final String SESSION_TOKEN_EXPIRY_KEY = "oauth2_token_expiry";
    private static final String SESSION_ORIGINAL_URL_KEY = "oauth2_original_url";
    
    // Excluded paths (no authentication required)
    private static final String[] EXCLUDED_PATHS = {
        "/health", "/actuator", "/public", "/static", "/css", "/js", "/images", "/login/oauth2/code"
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
        
        String callbackPathParam = filterConfig.getInitParameter("azureAd.callbackPath");
        if (callbackPathParam != null && callbackPathParam.length() > 0) {
            callbackPath = callbackPathParam;
        }
        
        // Validate required configuration
        if (clientId == null || tenantId == null || redirectUri == null) {
            throw new ServletException("Missing required Azure AD configuration parameters. " +
                "Required: azureAd.clientId, azureAd.tenantId, azureAd.redirectUri");
        }
        
        // Construct Azure AD authorization endpoint
        authorizationEndpoint = String.format(
            "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tenantId);
        
        System.out.println("AzureADOAuth2Filter initialized for tenant: " + tenantId);
        System.out.println("Callback path: " + callbackPath);
    }
    
    /**
     * Main filter logic - handles OAuth2 authentication check
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
        if (isAuthenticated(session)) {
            // Check if token is expired
            if (isTokenExpired(session)) {
                // Clear session and force re-authentication
                clearSession(session);
                storeOriginalUrl(httpRequest, session);
                initiateAuthorizationFlow(httpRequest, httpResponse, session);
                return;
            }
            chain.doFilter(request, response);
            return;
        }
        
        // Store original URL for redirect after authentication
        storeOriginalUrl(httpRequest, session);
        
        // Initiate OAuth2 authorization flow
        initiateAuthorizationFlow(httpRequest, httpResponse, session);
    }
    
    /**
     * Clean up resources
     */
    public void destroy() {
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
     * Check if user is authenticated (has valid access token in session)
     */
    private boolean isAuthenticated(HttpSession session) {
        String accessToken = (String) session.getAttribute(SESSION_ACCESS_TOKEN_KEY);
        return accessToken != null && accessToken.length() > 0;
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
     * Store original requested URL for redirect after authentication
     */
    private void storeOriginalUrl(HttpServletRequest request, HttpSession session) {
        String queryString = request.getQueryString();
        String originalUrl = request.getRequestURI();
        
        if (queryString != null && queryString.length() > 0) {
            originalUrl = originalUrl + "?" + queryString;
        }
        
        session.setAttribute(SESSION_ORIGINAL_URL_KEY, originalUrl);
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
        
        System.out.println("Redirecting to Azure AD: " + authUrl.toString());
        
        // Redirect to Azure AD authorization endpoint
        response.sendRedirect(authUrl.toString());
    }
    
    /**
     * Clear authentication session
     */
    private void clearSession(HttpSession session) {
        session.removeAttribute(SESSION_ACCESS_TOKEN_KEY);
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