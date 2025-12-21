package com.example.legacyapp.filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

/**
 * Gateway Authentication Filter implementing OAuth flow with gateway endpoints.
 * 
 * This filter intercepts requests and performs authentication via:
 * 1. /auth/initiate - Initiates the OAuth flow and returns authorization URL
 * 2. /auth/validate-token - Validates the access token received from OAuth callback
 * 
 * Java 6 compatible implementation with comprehensive logging.
 * 
 * @author numaansystems
 * @version 1.0
 * @since 2025-12-21
 */
public class GatewayAuthenticationFilter implements Filter {
    
    private static final Log logger = LogFactory.getLog(GatewayAuthenticationFilter.class);
    
    // Configuration parameters
    private String gatewayBaseUrl;
    private String callbackUrl;
    private int connectionTimeout = 30000; // 30 seconds
    private int readTimeout = 30000; // 30 seconds
    
    // Session attribute keys
    private static final String SESSION_ACCESS_TOKEN = "oauth_access_token";
    private static final String SESSION_USER_INFO = "oauth_user_info";
    private static final String SESSION_STATE = "oauth_state";
    
    // Request parameter keys
    private static final String PARAM_CODE = "code";
    private static final String PARAM_STATE = "state";
    private static final String PARAM_ERROR = "error";
    
    // Paths to exclude from authentication
    private List<String> excludedPaths;

    /**
     * Initialize the filter with configuration parameters.
     */
    public void init(FilterConfig filterConfig) throws ServletException {
        logger.info("Initializing GatewayAuthenticationFilter");
        
        // Load configuration from filter init parameters
        gatewayBaseUrl = filterConfig.getInitParameter("gatewayBaseUrl");
        callbackUrl = filterConfig.getInitParameter("callbackUrl");
        
        String timeoutStr = filterConfig.getInitParameter("connectionTimeout");
        if (timeoutStr != null && timeoutStr.length() > 0) {
            try {
                connectionTimeout = Integer.parseInt(timeoutStr);
            } catch (NumberFormatException e) {
                logger.warn("Invalid connectionTimeout value, using default: " + connectionTimeout);
            }
        }
        
        timeoutStr = filterConfig.getInitParameter("readTimeout");
        if (timeoutStr != null && timeoutStr.length() > 0) {
            try {
                readTimeout = Integer.parseInt(timeoutStr);
            } catch (NumberFormatException e) {
                logger.warn("Invalid readTimeout value, using default: " + readTimeout);
            }
        }
        
        // Initialize excluded paths
        excludedPaths = new ArrayList<String>();
        excludedPaths.add("/auth/callback");
        excludedPaths.add("/public");
        excludedPaths.add("/health");
        excludedPaths.add("/static");
        
        String customExcludedPaths = filterConfig.getInitParameter("excludedPaths");
        if (customExcludedPaths != null && customExcludedPaths.length() > 0) {
            String[] paths = customExcludedPaths.split(",");
            for (int i = 0; i < paths.length; i++) {
                excludedPaths.add(paths[i].trim());
            }
        }
        
        // Validate required configuration
        if (gatewayBaseUrl == null || gatewayBaseUrl.length() == 0) {
            throw new ServletException("gatewayBaseUrl is required");
        }
        if (callbackUrl == null || callbackUrl.length() == 0) {
            throw new ServletException("callbackUrl is required");
        }
        
        logger.info("GatewayAuthenticationFilter initialized successfully");
        logger.info("Gateway Base URL: " + gatewayBaseUrl);
        logger.info("Callback URL: " + callbackUrl);
        logger.info("Connection Timeout: " + connectionTimeout + "ms");
        logger.info("Read Timeout: " + readTimeout + "ms");
        logger.info("Excluded Paths: " + excludedPaths.toString());
    }

    /**
     * Main filter logic for authentication.
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        String requestUri = httpRequest.getRequestURI();
        String contextPath = httpRequest.getContextPath();
        String path = requestUri.substring(contextPath.length());
        
        logger.debug("Processing request for path: " + path);
        
        // Check if path should be excluded from authentication
        if (isExcludedPath(path)) {
            logger.debug("Path excluded from authentication: " + path);
            chain.doFilter(request, response);
            return;
        }
        
        HttpSession session = httpRequest.getSession(true);
        
        // Handle OAuth callback
        if (path.startsWith("/auth/callback")) {
            handleOAuthCallback(httpRequest, httpResponse, session);
            return;
        }
        
        // Check if user is already authenticated
        String accessToken = (String) session.getAttribute(SESSION_ACCESS_TOKEN);
        if (accessToken != null && accessToken.length() > 0) {
            logger.debug("User already authenticated with access token");
            // Validate token is still valid
            if (validateToken(accessToken)) {
                logger.debug("Access token is valid, proceeding with request");
                chain.doFilter(request, response);
                return;
            } else {
                logger.info("Access token is invalid or expired, initiating new authentication");
                session.removeAttribute(SESSION_ACCESS_TOKEN);
                session.removeAttribute(SESSION_USER_INFO);
            }
        }
        
        // Initiate OAuth flow
        logger.info("User not authenticated, initiating OAuth flow");
        initiateOAuthFlow(httpRequest, httpResponse, session);
    }

    /**
     * Initiates the OAuth flow by calling /auth/initiate endpoint.
     */
    private void initiateOAuthFlow(HttpServletRequest request, HttpServletResponse response, 
                                    HttpSession session) throws IOException {
        logger.info("Initiating OAuth flow via /auth/initiate endpoint");
        
        HttpURLConnection conn = null;
        BufferedReader reader = null;
        
        try {
            // Generate and store state parameter for CSRF protection
            String state = generateState();
            session.setAttribute(SESSION_STATE, state);
            logger.debug("Generated OAuth state: " + state);
            
            // Build request to /auth/initiate
            URL url = new URL(gatewayBaseUrl + "/auth/initiate");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept", "application/json");
            conn.setConnectTimeout(connectionTimeout);
            conn.setReadTimeout(readTimeout);
            conn.setDoOutput(true);
            
            // Build request body
            StringBuilder requestBody = new StringBuilder();
            requestBody.append("callback_url=").append(URLEncoder.encode(callbackUrl, "UTF-8"));
            requestBody.append("&state=").append(URLEncoder.encode(state, "UTF-8"));
            
            // Send request
            OutputStream os = conn.getOutputStream();
            os.write(requestBody.toString().getBytes("UTF-8"));
            os.flush();
            os.close();
            
            int responseCode = conn.getResponseCode();
            logger.info("Received response from /auth/initiate: " + responseCode);
            
            if (responseCode == HttpURLConnection.HTTP_OK) {
                // Read response
                reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
                StringBuilder responseBuilder = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    responseBuilder.append(line);
                }
                
                String responseBody = responseBuilder.toString();
                logger.debug("Response body: " + responseBody);
                
                // Parse authorization URL from response
                String authUrl = extractAuthorizationUrl(responseBody);
                if (authUrl != null && authUrl.length() > 0) {
                    logger.info("Redirecting to authorization URL: " + authUrl);
                    response.sendRedirect(authUrl);
                } else {
                    logger.error("Failed to extract authorization URL from response");
                    sendErrorResponse(response, "Failed to initiate authentication");
                }
            } else {
                logger.error("Failed to initiate OAuth flow. Response code: " + responseCode);
                String errorMsg = readErrorResponse(conn);
                logger.error("Error response: " + errorMsg);
                sendErrorResponse(response, "Authentication service unavailable");
            }
            
        } catch (IOException e) {
            logger.error("Error initiating OAuth flow: " + e.getMessage(), e);
            throw e;
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    logger.warn("Error closing reader: " + e.getMessage());
                }
            }
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /**
     * Handles the OAuth callback after user authorization.
     */
    private void handleOAuthCallback(HttpServletRequest request, HttpServletResponse response, 
                                     HttpSession session) throws IOException {
        logger.info("Handling OAuth callback");
        
        // Check for error parameter
        String error = request.getParameter(PARAM_ERROR);
        if (error != null && error.length() > 0) {
            logger.error("OAuth error received: " + error);
            sendErrorResponse(response, "Authentication failed: " + error);
            return;
        }
        
        // Get authorization code and state
        String code = request.getParameter(PARAM_CODE);
        String state = request.getParameter(PARAM_STATE);
        
        if (code == null || code.length() == 0) {
            logger.error("Authorization code not received in callback");
            sendErrorResponse(response, "Invalid callback parameters");
            return;
        }
        
        // Verify state parameter for CSRF protection
        String sessionState = (String) session.getAttribute(SESSION_STATE);
        if (sessionState == null || !sessionState.equals(state)) {
            logger.error("State parameter mismatch. Expected: " + sessionState + ", Received: " + state);
            sendErrorResponse(response, "Invalid state parameter");
            return;
        }
        
        logger.debug("Authorization code received: " + code);
        logger.debug("State parameter verified successfully");
        
        // Validate token with gateway
        String accessToken = validateTokenWithGateway(code, state);
        if (accessToken != null && accessToken.length() > 0) {
            logger.info("Access token received and validated successfully");
            session.setAttribute(SESSION_ACCESS_TOKEN, accessToken);
            session.removeAttribute(SESSION_STATE);
            
            // Redirect to original requested page or home
            String redirectUrl = (String) session.getAttribute("original_request_url");
            if (redirectUrl == null || redirectUrl.length() == 0) {
                redirectUrl = request.getContextPath() + "/";
            }
            logger.info("Redirecting to: " + redirectUrl);
            response.sendRedirect(redirectUrl);
        } else {
            logger.error("Failed to validate token with gateway");
            sendErrorResponse(response, "Token validation failed");
        }
    }

    /**
     * Validates the authorization code by calling /auth/validate-token endpoint.
     */
    private String validateTokenWithGateway(String code, String state) {
        logger.info("Validating token via /auth/validate-token endpoint");
        
        HttpURLConnection conn = null;
        BufferedReader reader = null;
        
        try {
            // Build request to /auth/validate-token
            URL url = new URL(gatewayBaseUrl + "/auth/validate-token");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept", "application/json");
            conn.setConnectTimeout(connectionTimeout);
            conn.setReadTimeout(readTimeout);
            conn.setDoOutput(true);
            
            // Build request body
            StringBuilder requestBody = new StringBuilder();
            requestBody.append("code=").append(URLEncoder.encode(code, "UTF-8"));
            requestBody.append("&state=").append(URLEncoder.encode(state, "UTF-8"));
            requestBody.append("&callback_url=").append(URLEncoder.encode(callbackUrl, "UTF-8"));
            
            // Send request
            OutputStream os = conn.getOutputStream();
            os.write(requestBody.toString().getBytes("UTF-8"));
            os.flush();
            os.close();
            
            int responseCode = conn.getResponseCode();
            logger.info("Received response from /auth/validate-token: " + responseCode);
            
            if (responseCode == HttpURLConnection.HTTP_OK) {
                // Read response
                reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
                StringBuilder responseBuilder = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    responseBuilder.append(line);
                }
                
                String responseBody = responseBuilder.toString();
                logger.debug("Response body: " + responseBody);
                
                // Extract access token from response
                String accessToken = extractAccessToken(responseBody);
                if (accessToken != null && accessToken.length() > 0) {
                    logger.info("Access token extracted successfully");
                    return accessToken;
                } else {
                    logger.error("Failed to extract access token from response");
                }
            } else {
                logger.error("Token validation failed. Response code: " + responseCode);
                String errorMsg = readErrorResponse(conn);
                logger.error("Error response: " + errorMsg);
            }
            
        } catch (IOException e) {
            logger.error("Error validating token: " + e.getMessage(), e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    logger.warn("Error closing reader: " + e.getMessage());
                }
            }
            if (conn != null) {
                conn.disconnect();
            }
        }
        
        return null;
    }

    /**
     * Validates if an access token is still valid.
     */
    private boolean validateToken(String accessToken) {
        logger.debug("Validating existing access token");
        
        // Simple validation - in production, you might want to call a token introspection endpoint
        // For now, we'll assume tokens are valid if they exist
        // You can enhance this by calling a gateway endpoint to verify token validity
        
        if (accessToken == null || accessToken.length() == 0) {
            return false;
        }
        
        // Could implement token expiry check here if token contains expiry information
        // Or call a gateway endpoint to verify token validity
        
        return true;
    }

    /**
     * Checks if the given path should be excluded from authentication.
     */
    private boolean isExcludedPath(String path) {
        for (int i = 0; i < excludedPaths.size(); i++) {
            String excludedPath = (String) excludedPaths.get(i);
            if (path.startsWith(excludedPath)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Generates a random state parameter for CSRF protection.
     * Java 6 compatible implementation.
     */
    private String generateState() {
        // Simple random string generation (Java 6 compatible)
        StringBuilder state = new StringBuilder();
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        java.util.Random random = new java.util.Random();
        
        for (int i = 0; i < 32; i++) {
            state.append(chars.charAt(random.nextInt(chars.length())));
        }
        
        return state.toString();
    }

    /**
     * Extracts authorization URL from JSON response.
     * Simple JSON parsing without external libraries (Java 6 compatible).
     */
    private String extractAuthorizationUrl(String jsonResponse) {
        // Simple JSON parsing for "authorization_url" field
        String key = "\"authorization_url\"";
        int keyIndex = jsonResponse.indexOf(key);
        
        if (keyIndex == -1) {
            // Try alternative key names
            key = "\"authorizationUrl\"";
            keyIndex = jsonResponse.indexOf(key);
        }
        
        if (keyIndex == -1) {
            key = "\"auth_url\"";
            keyIndex = jsonResponse.indexOf(key);
        }
        
        if (keyIndex != -1) {
            int valueStart = jsonResponse.indexOf("\"", keyIndex + key.length());
            if (valueStart != -1) {
                int valueEnd = jsonResponse.indexOf("\"", valueStart + 1);
                if (valueEnd != -1) {
                    return jsonResponse.substring(valueStart + 1, valueEnd);
                }
            }
        }
        
        return null;
    }

    /**
     * Extracts access token from JSON response.
     * Simple JSON parsing without external libraries (Java 6 compatible).
     */
    private String extractAccessToken(String jsonResponse) {
        // Simple JSON parsing for "access_token" field
        String key = "\"access_token\"";
        int keyIndex = jsonResponse.indexOf(key);
        
        if (keyIndex == -1) {
            // Try alternative key names
            key = "\"accessToken\"";
            keyIndex = jsonResponse.indexOf(key);
        }
        
        if (keyIndex == -1) {
            key = "\"token\"";
            keyIndex = jsonResponse.indexOf(key);
        }
        
        if (keyIndex != -1) {
            int valueStart = jsonResponse.indexOf("\"", keyIndex + key.length());
            if (valueStart != -1) {
                int valueEnd = jsonResponse.indexOf("\"", valueStart + 1);
                if (valueEnd != -1) {
                    return jsonResponse.substring(valueStart + 1, valueEnd);
                }
            }
        }
        
        return null;
    }

    /**
     * Reads error response from failed HTTP connection.
     */
    private String readErrorResponse(HttpURLConnection conn) {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(conn.getErrorStream(), "UTF-8"));
            StringBuilder errorBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                errorBuilder.append(line);
            }
            return errorBuilder.toString();
        } catch (Exception e) {
            logger.warn("Error reading error response: " + e.getMessage());
            return "";
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
        }
    }

    /**
     * Sends error response to client.
     */
    private void sendErrorResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("text/html");
        response.getWriter().write("<html><body><h1>Authentication Error</h1><p>" + message + "</p></body></html>");
    }

    /**
     * Cleanup resources when filter is destroyed.
     */
    public void destroy() {
        logger.info("Destroying GatewayAuthenticationFilter");
        // Cleanup resources if needed
    }
}
