package com.numaansystems.gateway.controller;

import com.numaansystems.gateway.service.ExchangeTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j. Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory. annotation.Value;
import org.springframework.http.ResponseEntity;
import org. springframework.security.core.Authentication;
import org.springframework.security. core.context.SecurityContextHolder;
import org.springframework.security. web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net. URL;
import java.net. URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util. HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final ExchangeTokenService exchangeTokenService;

    @Value("${AZURE_TENANT_ID:}")
    private String azureTenantId;

    public AuthController(ExchangeTokenService exchangeTokenService) {
        this.exchangeTokenService = exchangeTokenService;
    }

    @GetMapping("/initiate")
    public void initiateAuth(@RequestParam String returnUrl,
                            @RequestParam(required = false, defaultValue = "true") boolean forceReauth,
                            HttpServletRequest request,
                            HttpServletResponse response,
                            Authentication authentication) throws IOException {
        
        logger.info("==================== AUTH INITIATE ====================");
        logger.info("ReturnUrl: {}", returnUrl);
        logger. info("ForceReauth: {}", forceReauth);
        logger.info("Current authentication: {}", authentication != null ? authentication.getName() : "none");
        
        // ALWAYS clear existing authentication state
        HttpSession session = request.getSession(false);
        if (session != null) {
            logger.info("Invalidating existing session: {}", session.getId());
            session.invalidate();
        }
        
        // Clear Spring Security context
        if (authentication != null) {
            logger.info("Clearing authentication for user: {}", authentication.getName());
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        SecurityContextHolder.clearContext();
        
        // Create fresh session
        session = request.getSession(true);
        logger.info("Created new session: {}", session.getId());
        
        // Parse returnUrl to build callback URL
        try {
            String callbackUrl = buildCallbackUrl(returnUrl);
            
            // Store both URLs in session
            session.setAttribute("returnUrl", callbackUrl);  // Where gateway redirects (callback servlet)
            session.setAttribute("finalReturnUrl", returnUrl);  // Where user ultimately goes (home.html)
            
            logger.info("Stored in session:");
            logger.info("  returnUrl (callback): {}", callbackUrl);
            logger.info("  finalReturnUrl (destination): {}", returnUrl);
            
        } catch (MalformedURLException e) {
            logger.error("Invalid returnUrl: {}", returnUrl, e);
            response.sendRedirect("/");
            return;
        }
        
        // Set forceReauth flag to add prompt=login to Azure AD request
        if (forceReauth) {
            session.setAttribute("forceReauth", true);
            logger.info("ForceReauth flag set - will add prompt=login to Azure AD request");
        }
        
        // Redirect to OAuth2 authorization endpoint
        String redirectUrl = request.getContextPath() + "/oauth2/authorization/azure";
        logger.info("Redirecting to: {}", redirectUrl);
        logger.info("=======================================================");
        
        response.sendRedirect(redirectUrl);
    }

    /**
     * Build callback URL from returnUrl
     * E.g., http://localhost:8080/myapp/home.html -> http://localhost:8080/myapp/auth/callback
     */
    private String buildCallbackUrl(String returnUrl) throws MalformedURLException {
        URL url = new URL(returnUrl);
        
        String protocol = url.getProtocol();
        String host = url.getHost();
        int port = url.getPort();
        String path = url.getPath();
        
        // Build base URL
        StringBuilder baseUrl = new StringBuilder();
        baseUrl.append(protocol). append("://").append(host);
        if (port != -1 && port != 80 && port != 443) {
            baseUrl.append(":").append(port);
        }
        
        // Extract context path from path
        // E.g., /myapp/home.html -> /myapp
        String contextPath = "";
        if (path != null && !path.isEmpty()) {
            int secondSlash = path.indexOf('/', 1);
            if (secondSlash > 0) {
                contextPath = path.substring(0, secondSlash);
            } else if (path.length() > 1 && ! path.contains(". ")) {
                contextPath = path;
            }
        }
        
        return baseUrl.toString() + contextPath + "/auth/callback";
    }

    @PostMapping("/validate-token")
    public ResponseEntity<Map<String, Object>> validateToken(@RequestParam String token,
                                                             HttpServletRequest request) {
        
        logger.info("Token validation requested from: {}", request.getRemoteAddr());
        
        ExchangeTokenService.ExchangeTokenData tokenData = exchangeTokenService.validateAndRemoveToken(token);
        
        if (tokenData == null) {
            logger.warn("Token validation failed: invalid or expired token");
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse. put("error", "Invalid or expired token");
            return ResponseEntity. status(401).body(errorResponse);
        }
        
        logger.info("Token validated successfully for user: {}", tokenData.username);
        
        Map<String, Object> successResponse = new HashMap<>();
        successResponse.put("success", true);
        successResponse.put("username", tokenData.username);
        successResponse.put("email", tokenData.email);
        successResponse.put("name", tokenData. name);
        successResponse.put("authorities", tokenData.authorities);
        
        return ResponseEntity. ok(successResponse);
    }

    @GetMapping("/logout")
    public void logout(@RequestParam(required = false) String returnUrl,
                      HttpSession session,
                      HttpServletRequest request,
                      HttpServletResponse response,
                      Authentication authentication) throws IOException {
        
        logger.info("==================== LOGOUT ====================");
        logger. info("ReturnUrl: {}", returnUrl);
        logger.info("Current user: {}", authentication != null ? authentication.getName() : "none");
        
        // Invalidate local session
        if (session != null) {
            logger.info("Invalidating session: {}", session.getId());
            session.invalidate();
        }
        
        // Clear Spring Security context
        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        SecurityContextHolder.clearContext();
        
        // Build Azure AD logout URL
        String azureLogoutUrl = buildAzureLogoutUrl(returnUrl, request);
        
        logger.info("Redirecting to Azure AD logout: {}", azureLogoutUrl);
        logger.info("=================================================");
        
        response.sendRedirect(azureLogoutUrl);
    }

    /**
     * Build Azure AD logout URL with post_logout_redirect_uri
     */
    private String buildAzureLogoutUrl(String returnUrl, HttpServletRequest request) {
        if (azureTenantId == null || azureTenantId.isEmpty()) {
            logger.warn("AZURE_TENANT_ID not configured, skipping Azure AD logout");
            return returnUrl != null ? returnUrl : "/";
        }
        
        // Determine where to redirect after Azure AD logout
        String postLogoutRedirectUri;
        if (returnUrl != null && !returnUrl.isEmpty()) {
            postLogoutRedirectUri = returnUrl;
        } else {
            // Default to gateway root
            String scheme = request.getScheme();
            String serverName = request.getServerName();
            int serverPort = request. getServerPort();
            String contextPath = request.getContextPath();
            
            String portPart = "";
            if ((scheme. equals("http") && serverPort != 80) || 
                (scheme.equals("https") && serverPort != 443)) {
                portPart = ":" + serverPort;
            }
            
            postLogoutRedirectUri = scheme + "://" + serverName + portPart + contextPath + "/";
        }
        
        // Build Azure AD logout URL
        String azureLogoutUrl = String.format(
            "https://login.microsoftonline.com/%s/oauth2/v2.0/logout?post_logout_redirect_uri=%s",
            azureTenantId,
            URLEncoder.encode(postLogoutRedirectUri, StandardCharsets.UTF_8)
        );
        
        return azureLogoutUrl;
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> healthInfo = new HashMap<>();
        healthInfo.put("status", "UP");
        healthInfo.put("service", "azure-ad-gateway");
        healthInfo.put("version", "1.0.0");
        healthInfo.put("activeTokens", exchangeTokenService.getActiveTokenCount());
        
        return ResponseEntity.ok(healthInfo);
    }
}
