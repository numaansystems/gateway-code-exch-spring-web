package com.example.legacyapp.filter;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.Base64;
import org.json.JSONObject;

/**
 * Gateway Authentication Filter for Legacy Applications
 * 
 * This filter integrates legacy Java web applications with a centralized OAuth2 gateway.
 * It handles the complete OAuth2 authorization code flow with PKCE (Proof Key for Code Exchange).
 * 
 * Features:
 * - OAuth2 authorization code flow with PKCE
 * - Session management and validation
 * - Path and file extension exclusions
 * - Loop detection to prevent infinite redirects
 * - Comprehensive error handling
 * 
 * @author Gateway Integration Team
 * @version 1.0
 */
public class GatewayAuthenticationFilter implements Filter {
    
    private String gatewayUrl;
    private List<String> excludedPaths;
    private List<String> excludedExtensions;
    
    // Session attribute keys
    private static final String SESSION_USER_INFO = "userInfo";
    private static final String SESSION_ACCESS_TOKEN = "accessToken";
    private static final String SESSION_CODE_VERIFIER = "codeVerifier";
    private static final String SESSION_AUTH_ATTEMPTS = "authAttempts";
    
    // OAuth2 constants
    private static final String OAUTH_STATE_PARAM = "state";
    private static final String OAUTH_CODE_PARAM = "code";
    private static final String OAUTH_ERROR_PARAM = "error";
    private static final int MAX_AUTH_ATTEMPTS = 3;
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Read gateway URL from filter configuration
        gatewayUrl = filterConfig.getInitParameter("gatewayUrl");
        if (gatewayUrl == null || gatewayUrl.trim().isEmpty()) {
            throw new ServletException("gatewayUrl parameter is required");
        }
        
        // Remove trailing slash for consistency
        if (gatewayUrl.endsWith("/")) {
            gatewayUrl = gatewayUrl.substring(0, gatewayUrl.length() - 1);
        }
        
        // Parse excluded paths (comma-separated)
        String excludedPathsParam = filterConfig.getInitParameter("excludedPaths");
        if (excludedPathsParam != null && !excludedPathsParam.trim().isEmpty()) {
            excludedPaths = Arrays.asList(excludedPathsParam.split(","));
            excludedPaths.replaceAll(String::trim);
        } else {
            excludedPaths = Arrays.asList();
        }
        
        // Parse excluded file extensions (comma-separated)
        String excludedExtensionsParam = filterConfig.getInitParameter("excludedExtensions");
        if (excludedExtensionsParam != null && !excludedExtensionsParam.trim().isEmpty()) {
            excludedExtensions = Arrays.asList(excludedExtensionsParam.split(","));
            excludedExtensions.replaceAll(String::trim);
        } else {
            excludedExtensions = Arrays.asList();
        }
        
        System.out.println("GatewayAuthenticationFilter initialized:");
        System.out.println("  Gateway URL: " + gatewayUrl);
        System.out.println("  Excluded Paths: " + excludedPaths);
        System.out.println("  Excluded Extensions: " + excludedExtensions);
    }
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        HttpSession session = httpRequest.getSession(true);
        
        String requestURI = httpRequest.getRequestURI();
        String contextPath = httpRequest.getContextPath();
        String path = requestURI.substring(contextPath.length());
        
        // Check if path should be excluded from authentication
        if (isExcludedPath(path)) {
            chain.doFilter(request, response);
            return;
        }
        
        // Handle OAuth2 callback
        String code = httpRequest.getParameter(OAUTH_CODE_PARAM);
        String state = httpRequest.getParameter(OAUTH_STATE_PARAM);
        String error = httpRequest.getParameter(OAUTH_ERROR_PARAM);
        
        if (error != null) {
            // OAuth2 error response
            httpResponse.sendRedirect(contextPath + "/error.html?error=" + 
                URLEncoder.encode(error, "UTF-8"));
            return;
        }
        
        if (code != null && state != null) {
            // This is an OAuth2 callback
            handleOAuthCallback(httpRequest, httpResponse, code, state);
            return;
        }
        
        // Check if user is already authenticated
        Object userInfo = session.getAttribute(SESSION_USER_INFO);
        if (userInfo != null) {
            // User is authenticated, validate token and proceed
            String accessToken = (String) session.getAttribute(SESSION_ACCESS_TOKEN);
            if (validateToken(accessToken)) {
                chain.doFilter(request, response);
                return;
            } else {
                // Token is invalid, clear session and re-authenticate
                session.invalidate();
                session = httpRequest.getSession(true);
            }
        }
        
        // Check for authentication loop
        Integer authAttempts = (Integer) session.getAttribute(SESSION_AUTH_ATTEMPTS);
        if (authAttempts != null && authAttempts >= MAX_AUTH_ATTEMPTS) {
            httpResponse.sendRedirect(contextPath + "/error.html?error=auth_loop");
            return;
        }
        
        // Increment auth attempts
        session.setAttribute(SESSION_AUTH_ATTEMPTS, 
            authAttempts == null ? 1 : authAttempts + 1);
        
        // Initiate OAuth2 authorization code flow with PKCE
        initiateOAuthFlow(httpRequest, httpResponse);
    }
    
    /**
     * Checks if the given path should be excluded from authentication
     */
    private boolean isExcludedPath(String path) {
        // Check excluded paths
        for (String excludedPath : excludedPaths) {
            if (path.startsWith(excludedPath)) {
                return true;
            }
        }
        
        // Check excluded file extensions
        for (String extension : excludedExtensions) {
            if (path.endsWith(extension)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Initiates the OAuth2 authorization code flow with PKCE
     */
    private void initiateOAuthFlow(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        
        HttpSession session = request.getSession();
        
        // Generate PKCE code verifier and challenge
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);
        
        // Store code verifier in session for later use
        session.setAttribute(SESSION_CODE_VERIFIER, codeVerifier);
        
        // Generate state parameter for CSRF protection
        String state = UUID.randomUUID().toString();
        session.setAttribute(OAUTH_STATE_PARAM, state);
        
        // Build redirect URI (callback URL)
        String redirectUri = getRedirectUri(request);
        
        // Build authorization URL
        StringBuilder authUrl = new StringBuilder(gatewayUrl);
        authUrl.append("/oauth/authorize?");
        authUrl.append("response_type=code");
        authUrl.append("&client_id=").append(URLEncoder.encode("legacy-app", "UTF-8"));
        authUrl.append("&redirect_uri=").append(URLEncoder.encode(redirectUri, "UTF-8"));
        authUrl.append("&state=").append(URLEncoder.encode(state, "UTF-8"));
        authUrl.append("&code_challenge=").append(URLEncoder.encode(codeChallenge, "UTF-8"));
        authUrl.append("&code_challenge_method=S256");
        
        // Redirect to gateway authorization endpoint
        response.sendRedirect(authUrl.toString());
    }
    
    /**
     * Handles the OAuth2 callback after user authentication at gateway
     */
    private void handleOAuthCallback(HttpServletRequest request, HttpServletResponse response,
                                     String code, String state) throws IOException {
        
        HttpSession session = request.getSession();
        String contextPath = request.getContextPath();
        
        // Validate state parameter (CSRF protection)
        String sessionState = (String) session.getAttribute(OAUTH_STATE_PARAM);
        if (sessionState == null || !sessionState.equals(state)) {
            response.sendRedirect(contextPath + "/error.html?error=invalid_state");
            return;
        }
        
        // Retrieve code verifier from session
        String codeVerifier = (String) session.getAttribute(SESSION_CODE_VERIFIER);
        if (codeVerifier == null) {
            response.sendRedirect(contextPath + "/error.html?error=no_code_verifier");
            return;
        }
        
        try {
            // Exchange authorization code for access token
            String redirectUri = getRedirectUri(request);
            JSONObject tokenResponse = exchangeCodeForToken(code, redirectUri, codeVerifier);
            
            if (tokenResponse == null) {
                response.sendRedirect(contextPath + "/error.html?error=token_exchange_failed");
                return;
            }
            
            String accessToken = tokenResponse.optString("access_token");
            if (accessToken == null || accessToken.isEmpty()) {
                response.sendRedirect(contextPath + "/error.html?error=no_access_token");
                return;
            }
            
            // Fetch user info from gateway
            JSONObject userInfo = fetchUserInfo(accessToken);
            if (userInfo == null) {
                response.sendRedirect(contextPath + "/error.html?error=user_info_failed");
                return;
            }
            
            // Validate that we have a username
            String username = userInfo.optString("username");
            if (username == null || username.isEmpty()) {
                response.sendRedirect(contextPath + "/error.html?error=no_username");
                return;
            }
            
            // Store user info and access token in session
            session.setAttribute(SESSION_USER_INFO, userInfo.toString());
            session.setAttribute(SESSION_ACCESS_TOKEN, accessToken);
            
            // Clear authentication attempt counter
            session.removeAttribute(SESSION_AUTH_ATTEMPTS);
            session.removeAttribute(OAUTH_STATE_PARAM);
            session.removeAttribute(SESSION_CODE_VERIFIER);
            
            // Redirect to originally requested page or home
            String targetUrl = contextPath + "/home.jsp";
            response.sendRedirect(targetUrl);
            
        } catch (Exception e) {
            System.err.println("Error during OAuth callback: " + e.getMessage());
            e.printStackTrace();
            response.sendRedirect(contextPath + "/error.html?error=exception");
        }
    }
    
    /**
     * Exchanges authorization code for access token
     */
    private JSONObject exchangeCodeForToken(String code, String redirectUri, String codeVerifier)
            throws IOException {
        
        URL url = new URL(gatewayUrl + "/oauth/token");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setDoOutput(true);
            
            // Build request body
            StringBuilder body = new StringBuilder();
            body.append("grant_type=authorization_code");
            body.append("&code=").append(URLEncoder.encode(code, "UTF-8"));
            body.append("&redirect_uri=").append(URLEncoder.encode(redirectUri, "UTF-8"));
            body.append("&client_id=").append(URLEncoder.encode("legacy-app", "UTF-8"));
            body.append("&code_verifier=").append(URLEncoder.encode(codeVerifier, "UTF-8"));
            
            // Send request
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.toString().getBytes(StandardCharsets.UTF_8));
            }
            
            // Read response
            int responseCode = conn.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = in.readLine()) != null) {
                    response.append(line);
                }
                in.close();
                
                return new JSONObject(response.toString());
            } else {
                System.err.println("Token exchange failed with status: " + responseCode);
                return null;
            }
            
        } finally {
            conn.disconnect();
        }
    }
    
    /**
     * Fetches user information from gateway using access token
     */
    private JSONObject fetchUserInfo(String accessToken) throws IOException {
        URL url = new URL(gatewayUrl + "/api/userinfo");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
            
            int responseCode = conn.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = in.readLine()) != null) {
                    response.append(line);
                }
                in.close();
                
                return new JSONObject(response.toString());
            } else {
                System.err.println("User info fetch failed with status: " + responseCode);
                return null;
            }
            
        } finally {
            conn.disconnect();
        }
    }
    
    /**
     * Validates the access token with the gateway
     */
    private boolean validateToken(String accessToken) {
        if (accessToken == null || accessToken.isEmpty()) {
            return false;
        }
        
        try {
            URL url = new URL(gatewayUrl + "/api/validate");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            
            try {
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Authorization", "Bearer " + accessToken);
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                
                int responseCode = conn.getResponseCode();
                return responseCode == HttpURLConnection.HTTP_OK;
                
            } finally {
                conn.disconnect();
            }
            
        } catch (IOException e) {
            System.err.println("Token validation failed: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Generates a random code verifier for PKCE
     */
    private String generateCodeVerifier() {
        byte[] randomBytes = new byte[32];
        new java.security.SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
    
    /**
     * Generates code challenge from code verifier using SHA-256
     */
    private String generateCodeChallenge(String codeVerifier) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate code challenge", e);
        }
    }
    
    /**
     * Constructs the redirect URI for OAuth2 callback
     */
    private String getRedirectUri(HttpServletRequest request) {
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        String contextPath = request.getContextPath();
        
        StringBuilder redirectUri = new StringBuilder();
        redirectUri.append(scheme).append("://").append(serverName);
        
        // Only include port if it's not the default for the scheme
        if (("http".equals(scheme) && serverPort != 80) ||
            ("https".equals(scheme) && serverPort != 443)) {
            redirectUri.append(":").append(serverPort);
        }
        
        redirectUri.append(contextPath);
        
        return redirectUri.toString();
    }
    
    @Override
    public void destroy() {
        // Cleanup if needed
        System.out.println("GatewayAuthenticationFilter destroyed");
    }
}