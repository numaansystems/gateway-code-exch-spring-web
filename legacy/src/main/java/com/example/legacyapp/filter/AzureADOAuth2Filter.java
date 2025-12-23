package com.example.legacyapp.filter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
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

import org.json.JSONObject;
import org.json.JSONTokener;

/**
 * Azure AD OAuth2 Filter - Java 6 Compatible
 * 
 * Direct Azure AD OAuth2 integration filter for Spring Framework 3
 * Handles authorization code flow, token exchange, and user authentication
 * without requiring a gateway intermediary.
 * 
 * Configuration required in web.xml or Spring configuration:
 * - azureAd.clientId
 * - azureAd.clientSecret
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
    private String clientSecret;
    private String tenantId;
    private String redirectUri;
    private String scope = "openid profile email";
    
    // Azure AD endpoints
    private String authorizationEndpoint;
    private String tokenEndpoint;
    private String userInfoEndpoint;
    
    // Session attribute keys
    private static final String SESSION_STATE_KEY = "oauth2_state";
    private static final String SESSION_ACCESS_TOKEN_KEY = "oauth2_access_token";
    private static final String SESSION_ID_TOKEN_KEY = "oauth2_id_token";
    private static final String SESSION_USER_INFO_KEY = "oauth2_user_info";
    private static final String SESSION_TOKEN_EXPIRY_KEY = "oauth2_token_expiry";
    
    // Request parameter keys
    private static final String PARAM_CODE = "code";
    private static final String PARAM_STATE = "state";
    private static final String PARAM_ERROR = "error";
    private static final String PARAM_ERROR_DESCRIPTION = "error_description";
    
    // Excluded paths (no authentication required)
    private static final String[] EXCLUDED_PATHS = {
        "/health", "/actuator", "/public", "/static", "/css", "/js", "/images"
    };
    
    /**
     * Initialize filter with configuration parameters
     */
    public void init(FilterConfig filterConfig) throws ServletException {
        // Read configuration from filter init parameters
        clientId = getConfigParameter(filterConfig, "azureAd.clientId");
        clientSecret = getConfigParameter(filterConfig, "azureAd.clientSecret");
        tenantId = getConfigParameter(filterConfig, "azureAd.tenantId");
        redirectUri = getConfigParameter(filterConfig, "azureAd.redirectUri");
        
        String scopeParam = filterConfig.getInitParameter("azureAd.scope");
        if (scopeParam != null && scopeParam.length() > 0) {
            scope = scopeParam;
        }
        
        // Validate required configuration
        if (clientId == null || clientSecret == null || tenantId == null || redirectUri == null) {
            throw new ServletException("Missing required Azure AD configuration parameters. " +
                "Required: azureAd.clientId, azureAd.clientSecret, azureAd.tenantId, azureAd.redirectUri");
        }
        
        // Construct Azure AD endpoints
        authorizationEndpoint = String.format(
            "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tenantId);
        tokenEndpoint = String.format(
            "https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantId);
        userInfoEndpoint = "https://graph.microsoft.com/v1.0/me";
        
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
        
        // Check if this is a callback from Azure AD
        String code = httpRequest.getParameter(PARAM_CODE);
        String state = httpRequest.getParameter(PARAM_STATE);
        String error = httpRequest.getParameter(PARAM_ERROR);
        
        // Handle OAuth2 error response
        if (error != null) {
            String errorDescription = httpRequest.getParameter(PARAM_ERROR_DESCRIPTION);
            handleAuthorizationError(httpResponse, error, errorDescription);
            return;
        }
        
        // Handle OAuth2 callback with authorization code
        if (code != null && state != null) {
            handleAuthorizationCallback(httpRequest, httpResponse, session, code, state);
            return;
        }
        
        // Check if user is already authenticated
        if (isAuthenticated(session)) {
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
     * Handle OAuth2 callback with authorization code
     */
    private void handleAuthorizationCallback(HttpServletRequest request,
                                            HttpServletResponse response,
                                            HttpSession session,
                                            String code,
                                            String state) throws IOException, ServletException {
        // Validate state parameter (CSRF protection)
        String sessionState = (String) session.getAttribute(SESSION_STATE_KEY);
        if (sessionState == null || !sessionState.equals(state)) {
            throw new ServletException("Invalid state parameter - possible CSRF attack");
        }
        
        // Remove state from session
        session.removeAttribute(SESSION_STATE_KEY);
        
        try {
            // Exchange authorization code for access token
            Map<String, String> tokens = exchangeCodeForToken(code);
            
            String accessToken = tokens.get("access_token");
            String idToken = tokens.get("id_token");
            String expiresIn = tokens.get("expires_in");
            
            // Store tokens in session
            session.setAttribute(SESSION_ACCESS_TOKEN_KEY, accessToken);
            if (idToken != null) {
                session.setAttribute(SESSION_ID_TOKEN_KEY, idToken);
            }
            
            // Calculate and store token expiry time
            if (expiresIn != null) {
                long expiryTime = System.currentTimeMillis() + 
                    (Long.parseLong(expiresIn) * 1000);
                session.setAttribute(SESSION_TOKEN_EXPIRY_KEY, new Long(expiryTime));
            }
            
            // Fetch and store user info
            Map<String, Object> userInfo = fetchUserInfo(accessToken);
            session.setAttribute(SESSION_USER_INFO_KEY, userInfo);
            
            // Redirect to original requested page or home
            String originalUrl = getOriginalRequestUrl(request);
            response.sendRedirect(originalUrl);
            
        } catch (Exception e) {
            throw new ServletException("Failed to complete OAuth2 flow", e);
        }
    }
    
    /**
     * Exchange authorization code for access token
     */
    private Map<String, String> exchangeCodeForToken(String code) throws IOException {
        // Build token request body
        StringBuilder requestBody = new StringBuilder();
        requestBody.append("client_id=").append(urlEncode(clientId));
        requestBody.append("&client_secret=").append(urlEncode(clientSecret));
        requestBody.append("&code=").append(urlEncode(code));
        requestBody.append("&redirect_uri=").append(urlEncode(redirectUri));
        requestBody.append("&grant_type=authorization_code");
        requestBody.append("&scope=").append(urlEncode(scope));
        
        // Send token request
        String responseBody = sendPostRequest(tokenEndpoint, requestBody.toString());
        
        // Parse JSON response
        JSONObject jsonResponse = new JSONObject(new JSONTokener(responseBody));
        
        Map<String, String> tokens = new HashMap<String, String>();
        tokens.put("access_token", jsonResponse.optString("access_token"));
        tokens.put("id_token", jsonResponse.optString("id_token"));
        tokens.put("expires_in", jsonResponse.optString("expires_in"));
        tokens.put("refresh_token", jsonResponse.optString("refresh_token"));
        
        return tokens;
    }
    
    /**
     * Fetch user information from Microsoft Graph API
     */
    private Map<String, Object> fetchUserInfo(String accessToken) throws IOException {
        String responseBody = sendGetRequest(userInfoEndpoint, accessToken);
        
        JSONObject jsonResponse = new JSONObject(new JSONTokener(responseBody));
        
        Map<String, Object> userInfo = new HashMap<String, Object>();
        userInfo.put("id", jsonResponse.optString("id"));
        userInfo.put("displayName", jsonResponse.optString("displayName"));
        userInfo.put("givenName", jsonResponse.optString("givenName"));
        userInfo.put("surname", jsonResponse.optString("surname"));
        userInfo.put("userPrincipalName", jsonResponse.optString("userPrincipalName"));
        userInfo.put("mail", jsonResponse.optString("mail"));
        userInfo.put("jobTitle", jsonResponse.optString("jobTitle"));
        
        return userInfo;
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
     * Handle authorization error from Azure AD
     */
    private void handleAuthorizationError(HttpServletResponse response, 
                                         String error, 
                                         String errorDescription) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("text/html");
        
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h1>Authentication Error</h1>");
        html.append("<p><strong>Error:</strong> ").append(escapeHtml(error)).append("</p>");
        if (errorDescription != null) {
            html.append("<p><strong>Description:</strong> ")
                .append(escapeHtml(errorDescription)).append("</p>");
        }
        html.append("<p><a href=\"/\">Return to home</a></p>");
        html.append("</body></html>");
        
        response.getWriter().write(html.toString());
    }
    
    /**
     * Send HTTP POST request
     */
    private String sendPostRequest(String urlString, String requestBody) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        try {
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            connection.setDoOutput(true);
            
            // Write request body
            OutputStream os = connection.getOutputStream();
            try {
                os.write(requestBody.getBytes("UTF-8"));
                os.flush();
            } finally {
                os.close();
            }
            
            // Read response
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                return readResponse(connection);
            } else {
                throw new IOException("HTTP error code: " + responseCode);
            }
        } finally {
            connection.disconnect();
        }
    }
    
    /**
     * Send HTTP GET request with bearer token
     */
    private String sendGetRequest(String urlString, String accessToken) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        try {
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Authorization", "Bearer " + accessToken);
            connection.setRequestProperty("Accept", "application/json");
            
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                return readResponse(connection);
            } else {
                throw new IOException("HTTP error code: " + responseCode);
            }
        } finally {
            connection.disconnect();
        }
    }
    
    /**
     * Read HTTP response body
     */
    private String readResponse(HttpURLConnection connection) throws IOException {
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream(), "UTF-8"));
        try {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            return response.toString();
        } finally {
            reader.close();
        }
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
     * Get original request URL for redirect after authentication
     */
    private String getOriginalRequestUrl(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        String requestUri = request.getRequestURI();
        String queryString = request.getQueryString();
        
        // Remove OAuth2 callback parameters
        if (queryString != null) {
            queryString = removeParameter(queryString, PARAM_CODE);
            queryString = removeParameter(queryString, PARAM_STATE);
        }
        
        if (queryString != null && queryString.length() > 0) {
            return requestUri + "?" + queryString;
        }
        return contextPath != null && contextPath.length() > 0 ? contextPath + "/" : "/";
    }
    
    /**
     * Remove parameter from query string
     */
    private String removeParameter(String queryString, String paramName) {
        String[] pairs = queryString.split("&");
        StringBuilder result = new StringBuilder();
        
        for (int i = 0; i < pairs.length; i++) {
            String pair = pairs[i];
            if (!pair.startsWith(paramName + "=")) {
                if (result.length() > 0) {
                    result.append("&");
                }
                result.append(pair);
            }
        }
        
        return result.toString();
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
     * Escape HTML special characters
     */
    private String escapeHtml(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }
}
