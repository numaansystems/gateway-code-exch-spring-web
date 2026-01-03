package com.example.legacyapp.servlet;

import com.example.legacyapp.util.AzureAdUtil;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

/**
 * Servlet to handle user logout.
 * Java 6 compatible implementation.
 * 
 * <p>Invalidates the HTTP session, clears SecurityContextHolder, and redirects
 * to Azure AD logout endpoint with post_logout_redirect_uri parameter.</p>
 * 
 * @author Legacy App Integration
 * @version 1.0
 */
public class LogoutServlet extends HttpServlet {
    
    private String tenantId;
    private String postLogoutRedirectUri;
    
    private String logoutEndpoint;
    
    /**
     * Initialize servlet with configuration parameters
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        
        // Read configuration from servlet init parameters
        tenantId = getConfigParameter(config, "azureAd.tenantId");
        postLogoutRedirectUri = getConfigParameter(config, "azureAd.postLogoutRedirectUri");
        
        // If postLogoutRedirectUri not configured, use context path
        if (postLogoutRedirectUri == null || postLogoutRedirectUri.length() == 0) {
            postLogoutRedirectUri = "/"; // Will be resolved relative to context
        }
        
        // Validate required configuration
        if (tenantId == null) {
            throw new ServletException("Missing required Azure AD configuration parameter: azureAd.tenantId");
        }
        
        // Validate tenant ID format (UUID or domain)
        if (!AzureAdUtil.isValidTenantId(tenantId)) {
            throw new ServletException("Invalid Azure AD tenant ID format: " + tenantId);
        }
        
        // Construct Azure AD logout endpoint
        logoutEndpoint = String.format(
            "https://login.microsoftonline.com/%s/oauth2/v2.0/logout", tenantId);
        
        System.out.println("LogoutServlet initialized for tenant: " + tenantId);
    }
    
    /**
     * Handle GET request - perform logout
     */
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        System.out.println("LogoutServlet: Processing logout request");
        
        // Invalidate HTTP session
        HttpSession session = request.getSession(false);
        if (session != null) {
            System.out.println("LogoutServlet: Invalidating session: " + session.getId());
            session.invalidate();
        }
        
        // Clear SecurityContextHolder
        SecurityContextHolder.clearContext();
        System.out.println("LogoutServlet: Cleared SecurityContextHolder");
        
        // Build full post-logout redirect URI
        String fullPostLogoutUri = buildFullRedirectUri(request);
        
        // Build Azure AD logout URL
        StringBuilder logoutUrl = new StringBuilder();
        logoutUrl.append(logoutEndpoint);
        logoutUrl.append("?post_logout_redirect_uri=").append(urlEncode(fullPostLogoutUri));
        
        String azureLogoutUrl = logoutUrl.toString();
        System.out.println("LogoutServlet: Redirecting to Azure AD logout: " + azureLogoutUrl);
        
        response.sendRedirect(azureLogoutUrl);
    }
    
    /**
     * Handle POST request - same as GET
     */
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doGet(request, response);
    }
    
    /**
     * Build full post-logout redirect URI
     */
    private String buildFullRedirectUri(HttpServletRequest request) {
        // If postLogoutRedirectUri is already absolute, use it as-is
        if (postLogoutRedirectUri.startsWith("http://") || 
            postLogoutRedirectUri.startsWith("https://")) {
            return postLogoutRedirectUri;
        }
        
        // Build absolute URL from request
        StringBuilder fullUri = new StringBuilder();
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        String contextPath = request.getContextPath();
        
        fullUri.append(scheme).append("://").append(serverName);
        
        // Only include port if non-standard
        boolean includePort = (scheme.equals("http") && serverPort != 80) ||
                              (scheme.equals("https") && serverPort != 443);
        
        if (includePort) {
            fullUri.append(":").append(serverPort);
        }
        
        // Add context path if present
        if (contextPath != null && contextPath.length() > 0) {
            fullUri.append(contextPath);
        }
        
        // Add post-logout redirect URI
        if (!postLogoutRedirectUri.startsWith("/")) {
            fullUri.append("/");
        }
        fullUri.append(postLogoutRedirectUri);
        
        return fullUri.toString();
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
}
