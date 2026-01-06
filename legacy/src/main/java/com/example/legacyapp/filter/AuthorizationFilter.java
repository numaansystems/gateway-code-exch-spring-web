package com.example.legacyapp.filter;

import com.example.legacyapp.util.SecurityContextUtil;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Authorization filter that validates HttpSession authentication on every request.
 * Java 6 compatible implementation.
 * 
 * <p><strong>Performance Note:</strong> This filter is optimized for high throughput.
 * It ONLY reads from existing session attributes and does NOT make any database calls.
 * User authorities are loaded from the database once during login by AzureADCallbackFilter
 * and then cached in the session for the duration of the user's session.</p>
 * 
 * <p>This filter checks for authenticated session state on all requests
 * except excluded paths. If session is missing or not authenticated, redirects to
 * Azure AD login. If valid, loads user info from session and populates
 * SecurityContextHolder for Spring Security integration.</p>
 * 
 * <p><strong>Separation of Concerns:</strong></p>
 * <ul>
 *   <li><strong>AuthorizationFilter (this class)</strong>: Validates authentication on every request (no DB calls)</li>
 *   <li><strong>AzureADCallbackFilter</strong>: Loads authorities from database once during OAuth2 login</li>
 * </ul>
 * 
 * @author Legacy App Integration
 * @version 1.0
 */
public class AuthorizationFilter implements Filter {
    
    private Set<String> excludedPaths;
    
    // Session attribute keys - must match AzureADCallbackFilter
    private static final String SESSION_AUTHENTICATED_KEY = "authenticated";
    private static final String SESSION_USER_PRINCIPAL_KEY = "userPrincipal";
    private static final String SESSION_AUTHORITIES_KEY = "oauth2_authorities";
    private static final String SESSION_USER_INFO_KEY = "oauth2_user_info";
    
    // Request attribute keys
    private static final String REQUEST_USER_PRINCIPAL_KEY = "userPrincipal";
    private static final String REQUEST_AUTHORITIES_KEY = "authorities";
    
    /**
     * Initialize filter with configuration parameters
     */
    public void init(FilterConfig filterConfig) throws ServletException {
        // Parse excluded paths
        String excludedPathsParam = filterConfig.getInitParameter("excludedPaths");
        excludedPaths = new HashSet<String>();
        
        if (excludedPathsParam != null && excludedPathsParam.length() > 0) {
            String[] paths = excludedPathsParam.split(",");
            for (int i = 0; i < paths.length; i++) {
                String path = paths[i].trim();
                if (path.length() > 0) {
                    excludedPaths.add(path);
                }
            }
        }
        
        System.out.println("AuthorizationFilter: Excluded paths: " + excludedPaths);
        System.out.println("AuthorizationFilter initialized (authentication validation only - no DB calls)");
    }
    
    /**
     * Main filter logic - validates HttpSession
     */
    @SuppressWarnings("unchecked")
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        String requestUri = httpRequest.getRequestURI();
        String contextPath = httpRequest.getContextPath();
        
        // Get path relative to context
        String path = requestUri;
        if (contextPath != null && contextPath.length() > 0 && 
            requestUri.startsWith(contextPath)) {
            path = requestUri.substring(contextPath.length());
        }
        
        // Check if path is excluded
        if (isPathExcluded(path)) {
            chain.doFilter(request, response);
            return;
        }
        
        // Check for valid session
        HttpSession session = httpRequest.getSession(false);
        if (session == null) {
            System.out.println("AuthorizationFilter: No session found, redirecting to login");
            redirectToLogin(httpRequest, httpResponse);
            return;
        }
        
        Boolean authenticated = (Boolean) session.getAttribute(SESSION_AUTHENTICATED_KEY);
        if (authenticated == null || !authenticated) {
            System.out.println("AuthorizationFilter: Session not authenticated, redirecting to login");
            redirectToLogin(httpRequest, httpResponse);
            return;
        }
        
        String userPrincipal = (String) session.getAttribute(SESSION_USER_PRINCIPAL_KEY);
        if (userPrincipal == null || userPrincipal.length() == 0) {
            System.err.println("AuthorizationFilter: No user principal in session, redirecting to login");
            redirectToLogin(httpRequest, httpResponse);
            return;
        }
        
        System.out.println("AuthorizationFilter: Valid session for user: " + userPrincipal);
        
        // Get authorities from session
        Collection authorities = (Collection) session.getAttribute(SESSION_AUTHORITIES_KEY);
        Map userInfo = (Map) session.getAttribute(SESSION_USER_INFO_KEY);
        
        if (authorities == null) {
            authorities = new ArrayList<String>();
        }
        
        System.out.println("AuthorizationFilter: User authorized with " + authorities.size() + " authorities");
        
        // Store user principal, authorities, and userInfo in request attributes for JSP/servlet access
        httpRequest.setAttribute(REQUEST_USER_PRINCIPAL_KEY, userPrincipal);
        httpRequest.setAttribute(REQUEST_AUTHORITIES_KEY, authorities);
        if (userInfo != null) {
            httpRequest.setAttribute("userInfo", userInfo);
        }
        
        // Populate SecurityContextHolder for Spring Security integration
        SecurityContextUtil.populateSecurityContext(session);
        
        // Continue filter chain
        chain.doFilter(request, response);
    }
    
    /**
     * Clean up resources
     */
    public void destroy() {
        System.out.println("AuthorizationFilter destroyed");
    }
    
    /**
     * Check if path is excluded from authorization
     */
    private boolean isPathExcluded(String path) {
        if (path == null || path.length() == 0) {
            return false;
        }
        
        // Check exact matches
        if (excludedPaths.contains(path)) {
            return true;
        }
        
        // Check wildcard matches (path/* pattern)
        for (String excludedPath : excludedPaths) {
            if (excludedPath.endsWith("/*")) {
                String prefix = excludedPath.substring(0, excludedPath.length() - 2);
                if (path.startsWith(prefix)) {
                    return true;
                }
            } else if (excludedPath.endsWith("*")) {
                String prefix = excludedPath.substring(0, excludedPath.length() - 1);
                if (path.startsWith(prefix)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Redirect to login page
     */
    private void redirectToLogin(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String contextPath = request.getContextPath();
        String loginUrl = (contextPath != null && contextPath.length() > 0) 
            ? contextPath + "/login/oauth2/azure" 
            : "/login/oauth2/azure";
        response.sendRedirect(loginUrl);
    }
}
