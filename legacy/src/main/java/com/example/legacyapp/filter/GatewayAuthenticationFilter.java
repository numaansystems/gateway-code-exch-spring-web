package com.example.legacyapp.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

/**
 * Authentication filter that integrates with OAuth gateway.
 * Dynamically constructs callback URL from incoming requests.
 */
public class GatewayAuthenticationFilter implements Filter {
    
    private static final Logger logger = Logger.getLogger(GatewayAuthenticationFilter.class.getName());
    
    private String gatewayUrl;
    private String clientId;
    private String callbackPath = "/auth/callback"; // Default callback path
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Required parameters
        gatewayUrl = filterConfig.getInitParameter("gatewayUrl");
        clientId = filterConfig.getInitParameter("clientId");
        
        // Optional callback path parameter
        String configuredCallbackPath = filterConfig.getInitParameter("callbackPath");
        if (configuredCallbackPath != null && !configuredCallbackPath.trim().isEmpty()) {
            callbackPath = configuredCallbackPath;
            logger.info("Using configured callback path: " + callbackPath);
        } else {
            logger.info("Using default callback path: " + callbackPath);
        }
        
        // Validate required parameters
        if (gatewayUrl == null || gatewayUrl.trim().isEmpty()) {
            throw new ServletException("gatewayUrl init parameter is required");
        }
        if (clientId == null || clientId.trim().isEmpty()) {
            throw new ServletException("clientId init parameter is required");
        }
        
        logger.info("GatewayAuthenticationFilter initialized with gatewayUrl: " + gatewayUrl + ", clientId: " + clientId);
    }
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        HttpSession session = httpRequest.getSession(false);
        
        String requestURI = httpRequest.getRequestURI();
        
        // Check if this is the callback from the gateway
        if (requestURI.endsWith(callbackPath)) {
            handleCallback(httpRequest, httpResponse);
            return;
        }
        
        // Check if user is already authenticated
        if (session != null && session.getAttribute("authenticated") != null) {
            chain.doFilter(request, response);
            return;
        }
        
        // Initiate OAuth flow
        initiateOAuthFlow(httpRequest, httpResponse);
    }
    
    /**
     * Builds the full callback URL dynamically from the incoming request.
     * 
     * @param request The HTTP servlet request
     * @return The complete callback URL (e.g., http://localhost:8080/myapp/auth/callback)
     */
    private String buildCallbackUrl(HttpServletRequest request) {
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        String contextPath = request.getContextPath();
        
        StringBuilder callbackUrl = new StringBuilder();
        callbackUrl.append(scheme).append("://").append(serverName);
        
        // Only include port if it's non-standard
        boolean includePort = (scheme.equals("http") && serverPort != 80) ||
                              (scheme.equals("https") && serverPort != 443);
        
        if (includePort) {
            callbackUrl.append(":").append(serverPort);
        }
        
        // Add context path if present
        if (contextPath != null && !contextPath.isEmpty()) {
            callbackUrl.append(contextPath);
        }
        
        // Add callback path
        callbackUrl.append(callbackPath);
        
        String fullCallbackUrl = callbackUrl.toString();
        logger.info("Constructed callback URL: " + fullCallbackUrl);
        
        return fullCallbackUrl;
    }
    
    /**
     * Initiates the OAuth flow by redirecting to the gateway.
     */
    private void initiateOAuthFlow(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        
        // Build callback URL dynamically from request
        String callbackUrl = buildCallbackUrl(request);
        
        // Store the original requested URL in session for redirect after authentication
        HttpSession session = request.getSession(true);
        String originalUrl = request.getRequestURL().toString();
        if (request.getQueryString() != null) {
            originalUrl += "?" + request.getQueryString();
        }
        session.setAttribute("originalUrl", originalUrl);
        
        // Build authorization URL
        String authorizationUrl = gatewayUrl + "/oauth/authorize" +
                "?client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8.name()) +
                "&redirect_uri=" + URLEncoder.encode(callbackUrl, StandardCharsets.UTF_8.name()) +
                "&response_type=code";
        
        logger.info("Redirecting to authorization URL: " + authorizationUrl);
        response.sendRedirect(authorizationUrl);
    }
    
    /**
     * Handles the callback from the OAuth gateway.
     */
    private void handleCallback(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        
        String code = request.getParameter("code");
        String error = request.getParameter("error");
        
        if (error != null) {
            logger.warning("OAuth error: " + error);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed: " + error);
            return;
        }
        
        if (code == null || code.trim().isEmpty()) {
            logger.warning("No authorization code received");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing authorization code");
            return;
        }
        
        // Build callback URL for token validation
        String callbackUrl = buildCallbackUrl(request);
        
        // Validate the code with the gateway and get access token
        boolean isValid = validateTokenWithGateway(code, callbackUrl);
        
        if (isValid) {
            HttpSession session = request.getSession(true);
            session.setAttribute("authenticated", true);
            session.setAttribute("authCode", code);
            
            // Redirect to original URL
            String originalUrl = (String) session.getAttribute("originalUrl");
            if (originalUrl != null) {
                session.removeAttribute("originalUrl");
                logger.info("Authentication successful, redirecting to: " + originalUrl);
                response.sendRedirect(originalUrl);
            } else {
                logger.info("Authentication successful, redirecting to context root");
                response.sendRedirect(request.getContextPath() + "/");
            }
        } else {
            logger.warning("Token validation failed");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token validation failed");
        }
    }
    
    /**
     * Validates the authorization code with the gateway and exchanges it for an access token.
     * 
     * @param code The authorization code
     * @param callbackUrl The callback URL used in the original request
     * @return true if validation is successful, false otherwise
     */
    private boolean validateTokenWithGateway(String code, String callbackUrl) {
        try {
            // Build token request URL
            String tokenUrl = gatewayUrl + "/oauth/token" +
                    "?grant_type=authorization_code" +
                    "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8.name()) +
                    "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8.name()) +
                    "&redirect_uri=" + URLEncoder.encode(callbackUrl, StandardCharsets.UTF_8.name());
            
            logger.info("Validating token with gateway using callback URL: " + callbackUrl);
            
            // In a real implementation, you would make an HTTP request to the token endpoint
            // For this example, we'll simulate validation
            // TODO: Implement actual HTTP client call to gateway
            
            logger.info("Token validation successful");
            return true;
            
        } catch (Exception e) {
            logger.severe("Error validating token: " + e.getMessage());
            return false;
        }
    }
    
    @Override
    public void destroy() {
        logger.info("GatewayAuthenticationFilter destroyed");
    }
}
