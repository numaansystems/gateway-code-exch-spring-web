package com.example.legacyapp.filter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Filter to handle OAuth2 callback from Azure AD.
 * This filter is mapped to /login/oauth2/code/azure path.
 * 
 * It processes the authorization code received from Azure AD,
 * exchanges it for an access token, and establishes a user session.
 * 
 * @author numaansystems
 * @since 2025-12-29
 */
public class AzureADCallbackFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(AzureADCallbackFilter.class);
    
    private static final String AZURE_TOKEN_ENDPOINT = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token";
    private static final String AZURE_USERINFO_ENDPOINT = "https://graph.microsoft.com/v1.0/me";
    
    private String clientId;
    private String clientSecret;
    private String tenantId;
    private String redirectUri;
    private ObjectMapper objectMapper;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Initialize configuration from filter config or environment variables
        this.clientId = getConfigValue(filterConfig, "azure.client.id", "AZURE_CLIENT_ID");
        this.clientSecret = getConfigValue(filterConfig, "azure.client.secret", "AZURE_CLIENT_SECRET");
        this.tenantId = getConfigValue(filterConfig, "azure.tenant.id", "AZURE_TENANT_ID");
        this.redirectUri = getConfigValue(filterConfig, "azure.redirect.uri", "AZURE_REDIRECT_URI");
        this.objectMapper = new ObjectMapper();
        
        logger.info("AzureADCallbackFilter initialized for tenant: {}", tenantId);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        String requestURI = httpRequest.getRequestURI();
        logger.debug("Processing Azure AD callback for URI: {}", requestURI);
        
        // Check if this is the callback path
        if (requestURI.endsWith("/login/oauth2/code/azure")) {
            handleAzureCallback(httpRequest, httpResponse);
        } else {
            chain.doFilter(request, response);
        }
    }

    /**
     * Handle the OAuth2 callback from Azure AD
     */
    private void handleAzureCallback(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        
        String code = request.getParameter("code");
        String state = request.getParameter("state");
        String error = request.getParameter("error");
        String errorDescription = request.getParameter("error_description");
        
        // Check for errors in the callback
        if (error != null) {
            logger.error("Azure AD authentication error: {} - {}", error, errorDescription);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, 
                "Authentication failed: " + errorDescription);
            return;
        }
        
        // Validate authorization code
        if (code == null || code.isEmpty()) {
            logger.error("No authorization code received from Azure AD");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, 
                "Missing authorization code");
            return;
        }
        
        // Validate state parameter (CSRF protection)
        HttpSession session = request.getSession(false);
        if (session != null && state != null) {
            String savedState = (String) session.getAttribute("oauth2_state");
            if (!state.equals(savedState)) {
                logger.error("State parameter mismatch - possible CSRF attack");
                response.sendError(HttpServletResponse.SC_FORBIDDEN, 
                    "Invalid state parameter");
                return;
            }
        }
        
        try {
            // Exchange authorization code for access token
            Map<String, String> tokenResponse = exchangeCodeForToken(code);
            String accessToken = tokenResponse.get("access_token");
            String idToken = tokenResponse.get("id_token");
            String refreshToken = tokenResponse.get("refresh_token");
            
            // Get user information from Microsoft Graph
            Map<String, Object> userInfo = getUserInfo(accessToken);
            
            // Create or update session with user information
            HttpSession userSession = request.getSession(true);
            userSession.setAttribute("authenticated", true);
            userSession.setAttribute("provider", "azure-ad");
            userSession.setAttribute("access_token", accessToken);
            userSession.setAttribute("id_token", idToken);
            if (refreshToken != null) {
                userSession.setAttribute("refresh_token", refreshToken);
            }
            userSession.setAttribute("user_info", userInfo);
            userSession.setAttribute("user_id", userInfo.get("id"));
            userSession.setAttribute("user_email", userInfo.get("userPrincipalName"));
            userSession.setAttribute("display_name", userInfo.get("displayName"));
            
            logger.info("Azure AD authentication successful for user: {}", 
                userInfo.get("userPrincipalName"));
            
            // Redirect to the original requested URL or home page
            String targetUrl = (String) userSession.getAttribute("oauth2_redirect_url");
            if (targetUrl == null || targetUrl.isEmpty()) {
                targetUrl = request.getContextPath() + "/";
            }
            
            // Clean up temporary session attributes
            userSession.removeAttribute("oauth2_state");
            userSession.removeAttribute("oauth2_redirect_url");
            
            response.sendRedirect(targetUrl);
            
        } catch (Exception e) {
            logger.error("Error during Azure AD token exchange or user info retrieval", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                "Authentication processing failed");
        }
    }

    /**
     * Exchange authorization code for access token
     */
    private Map<String, String> exchangeCodeForToken(String code) throws IOException {
        String tokenEndpoint = AZURE_TOKEN_ENDPOINT.replace("{tenant}", tenantId);
        
        // Build the token request body
        Map<String, String> params = new HashMap<>();
        params.put("client_id", clientId);
        params.put("client_secret", clientSecret);
        params.put("code", code);
        params.put("redirect_uri", redirectUri);
        params.put("grant_type", "authorization_code");
        params.put("scope", "openid profile email User.Read");
        
        String requestBody = buildFormUrlEncoded(params);
        
        // Make HTTP POST request to token endpoint
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) 
            new java.net.URL(tokenEndpoint).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);
        
        try (java.io.OutputStream os = conn.getOutputStream()) {
            os.write(requestBody.getBytes(StandardCharsets.UTF_8));
        }
        
        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            String errorResponse = new String(conn.getErrorStream().readAllBytes(), 
                StandardCharsets.UTF_8);
            logger.error("Token exchange failed with code {}: {}", responseCode, errorResponse);
            throw new IOException("Token exchange failed: " + errorResponse);
        }
        
        // Parse the JSON response
        JsonNode responseJson = objectMapper.readTree(conn.getInputStream());
        Map<String, String> result = new HashMap<>();
        result.put("access_token", responseJson.get("access_token").asText());
        result.put("id_token", responseJson.get("id_token").asText());
        if (responseJson.has("refresh_token")) {
            result.put("refresh_token", responseJson.get("refresh_token").asText());
        }
        
        return result;
    }

    /**
     * Get user information from Microsoft Graph API
     */
    private Map<String, Object> getUserInfo(String accessToken) throws IOException {
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) 
            new java.net.URL(AZURE_USERINFO_ENDPOINT).openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        conn.setRequestProperty("Accept", "application/json");
        
        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            String errorResponse = new String(conn.getErrorStream().readAllBytes(), 
                StandardCharsets.UTF_8);
            logger.error("User info retrieval failed with code {}: {}", responseCode, errorResponse);
            throw new IOException("Failed to get user info: " + errorResponse);
        }
        
        // Parse the JSON response
        JsonNode userInfoJson = objectMapper.readTree(conn.getInputStream());
        Map<String, Object> userInfo = new HashMap<>();
        
        userInfo.put("id", userInfoJson.has("id") ? userInfoJson.get("id").asText() : null);
        userInfo.put("displayName", userInfoJson.has("displayName") ? 
            userInfoJson.get("displayName").asText() : null);
        userInfo.put("givenName", userInfoJson.has("givenName") ? 
            userInfoJson.get("givenName").asText() : null);
        userInfo.put("surname", userInfoJson.has("surname") ? 
            userInfoJson.get("surname").asText() : null);
        userInfo.put("userPrincipalName", userInfoJson.has("userPrincipalName") ? 
            userInfoJson.get("userPrincipalName").asText() : null);
        userInfo.put("mail", userInfoJson.has("mail") ? 
            userInfoJson.get("mail").asText() : null);
        userInfo.put("jobTitle", userInfoJson.has("jobTitle") ? 
            userInfoJson.get("jobTitle").asText() : null);
        
        return userInfo;
    }

    /**
     * Build form URL encoded string from parameters
     */
    private String buildFormUrlEncoded(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (sb.length() > 0) {
                sb.append("&");
            }
            sb.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8));
            sb.append("=");
            sb.append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    /**
     * Get configuration value from filter config or environment variable
     */
    private String getConfigValue(FilterConfig filterConfig, String paramName, String envVarName) {
        String value = filterConfig.getInitParameter(paramName);
        if (value == null || value.isEmpty()) {
            value = System.getenv(envVarName);
        }
        return value;
    }

    @Override
    public void destroy() {
        logger.info("AzureADCallbackFilter destroyed");
    }
}
