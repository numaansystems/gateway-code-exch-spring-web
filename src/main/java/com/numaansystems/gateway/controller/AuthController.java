package com.numaansystems.gateway.controller;

import com.numaansystems.gateway.service.ExchangeTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org. springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * REST controller for authentication operations.
 * 
 * <p>Provides endpoints for initiating OAuth2 authentication, validating
 * exchange tokens, logout, and health checks.</p>
 * 
 * <h2>Endpoints</h2>
 * <ul>
 *   <li>GET /auth/initiate - Start OAuth2 authentication flow</li>
 *   <li>POST /auth/validate-token - Validate exchange token (backend-to-backend)</li>
 *   <li>GET /auth/logout - Logout and invalidate session</li>
 *   <li>GET /auth/health - Service health check</li>
 * </ul>
 * 
 * @author Numaan Systems
 * @version 0.1. 0
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final ExchangeTokenService exchangeTokenService;

    /**
     * Constructor injection of exchange token service.
     * 
     * @param exchangeTokenService service for token operations
     */
    public AuthController(ExchangeTokenService exchangeTokenService) {
        this.exchangeTokenService = exchangeTokenService;
    }

    /**
     * Initiates the OAuth2 authentication flow with Azure AD.
     * 
     * <p>This endpoint is called by the legacy application to start authentication. 
     * The returnUrl is stored in the session and the user is redirected to Azure AD
     * for authentication.</p>
     * 
     * <h3>Usage Example</h3>
     * <pre>
     * // Normal login (reuse existing session if available)
     * window.location. href = 'http://gateway.example.com/gateway/auth/initiate?returnUrl=' 
     *                       + encodeURIComponent('http://app.example.com/dashboard');
     * 
     * // Force re-authentication (always prompt for credentials)
     * window. location.href = 'http://gateway.example.com/gateway/auth/initiate? returnUrl=' 
     *                       + encodeURIComponent('http://app.example.com/dashboard')
     *                       + '&forceReauth=true';
     * </pre>
     * 
     * @param returnUrl the URL to return to after successful authentication (required)
     * @param forceReauth if true, forces re-authentication even if user is already logged in (optional, default: false)
     * @param request the HTTP request
     * @param response the HTTP response
     * @param session the HTTP session
     * @param authentication current authentication (may be null)
     * @throws IOException if redirect fails
     */
@GetMapping("/initiate")
public void initiateAuth(@RequestParam String returnUrl,
                        @RequestParam(required = false, defaultValue = "true") boolean forceReauth,  // Changed default to TRUE
                        HttpServletRequest request,
                        HttpServletResponse response,
                        HttpSession session,
                        Authentication authentication) throws IOException {
    
    logger.info("Authentication initiated with returnUrl: {}, forceReauth: {}", returnUrl, forceReauth);
    
    // Check if user is already authenticated
    boolean isAuthenticated = authentication != null 
        && authentication.isAuthenticated() 
        && !"anonymousUser".equals(authentication. getName());
    
    // ALWAYS force re-authentication for simplicity
    if (isAuthenticated) {
        logger.info("Forcing re-authentication for user: {}", authentication.getName());
        
        // Invalidate existing session
        if (session != null) {
            session.invalidate();
        }
        
        // Clear security context
        SecurityContextHolder.clearContext();
        
        // Create new session
        session = request.getSession(true);
        
        isAuthenticated = false;
    }
    
    logger.info("Initiating OAuth2 login flow");
    
    // Store returnUrl in session for use after OAuth2 callback
    session.setAttribute("returnUrl", returnUrl);
    
    // Store forceReauth flag for authorization request customization
    if (forceReauth) {
        session.setAttribute("forceReauth", true);
    }
    
    // Include context path in redirect
    String redirectUrl = request.getContextPath() + "/oauth2/authorization/azure";
    logger.info("Redirecting to: {}", redirectUrl);
    response.sendRedirect(redirectUrl);
}
    /**
     * Validates an exchange token and returns user information.
     * 
     * <p>This endpoint should be called by the legacy application's backend
     * (server-to-server) to validate the exchange token and retrieve user details.  
     * The token is single-use and will be removed after validation.</p>
     * 
     * <h3>Success Response (200 OK)</h3>
     * <pre>
     * {
     *   "success": true,
     *   "username": "user@example.com",
     *   "email": "user@example. com",
     *   "name": "John Doe",
     *   "authorities": ["ROLE_USER", "ROLE_ADMIN"]
     * }
     * </pre>
     * 
     * <h3>Error Response (401 Unauthorized)</h3>
     * <pre>
     * {
     *   "success": false,
     *   "error": "Invalid or expired token"
     * }
     * </pre>
     * 
     * @param token the exchange token to validate (required)
     * @param request the HTTP request (for logging)
     * @return response entity with user data or error message
     */
    @PostMapping("/validate-token")
    public ResponseEntity<Map<String, Object>> validateToken(@RequestParam String token,
                                                             HttpServletRequest request) {
        
        logger.info("Token validation requested from: {}", request.getRemoteAddr());
        
        // Validate and remove token (single-use)
        ExchangeTokenService.ExchangeTokenData tokenData = exchangeTokenService.validateAndRemoveToken(token);
        
        if (tokenData == null) {
            logger.warn("Token validation failed: invalid or expired token");
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("error", "Invalid or expired token");
            return ResponseEntity.status(401).body(errorResponse);
        }
        
        logger.info("Token validated successfully for user: {}", tokenData.username);
        
        // Build success response with user data
        Map<String, Object> successResponse = new HashMap<>();
        successResponse.put("success", true);
        successResponse.put("username", tokenData.username);
        successResponse.put("email", tokenData.email);
        successResponse.put("name", tokenData. name);
        successResponse.put("authorities", tokenData.authorities);
        
        return ResponseEntity. ok(successResponse);
    }

    /**
     * Logs out the user and invalidates the session.
     * 
     * <p>After logout, the user is redirected to the specified returnUrl
     * or to the root path if no returnUrl is provided.</p>
     * 
     * <h3>Usage Example</h3>
     * <pre>
     * window.location.href = 'http://gateway.example.com/gateway/auth/logout?returnUrl=' 
     *                       + encodeURIComponent('http://app.example.com/');
     * </pre>
     * 
     * @param returnUrl the URL to redirect to after logout (optional)
     * @param session the HTTP session to invalidate
     * @param response the HTTP response for redirect
     * @throws IOException if redirect fails
     */
    @GetMapping("/logout")
    public void logout(@RequestParam(required = false) String returnUrl,
                      HttpSession session,
                      HttpServletResponse response) throws IOException {
        
        logger.info("Logout requested");
        
        // Invalidate session
        if (session != null) {
            session. invalidate();
            logger.info("Session invalidated");
        }
        
        // Clear security context
        SecurityContextHolder.clearContext();
        logger.info("Security context cleared");
        
        // Redirect to returnUrl or root
        String redirectUrl = (returnUrl != null && !returnUrl.isEmpty()) ?  returnUrl : "/";
        logger.info("Redirecting to: {}", redirectUrl);
        response.sendRedirect(redirectUrl);
    }

    /**
     * Health check endpoint for monitoring. 
     * 
     * <p>Returns service status and metrics including the number of active
     * exchange tokens currently in memory.</p>
     * 
     * <h3>Response Example</h3>
     * <pre>
     * {
     *   "status": "UP",
     *   "service": "azure-ad-gateway",
     *   "version": "1.0.0",
     *   "activeTokens": 5
     * }
     * </pre>
     * 
     * @return response entity with health information
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> healthInfo = new HashMap<>();
        healthInfo.put("status", "UP");
        healthInfo.put("service", "azure-ad-gateway");
        healthInfo.put("version", "1.0.0");
        healthInfo.put("activeTokens", exchangeTokenService. getActiveTokenCount());
        
        return ResponseEntity.ok(healthInfo);
    }
}
