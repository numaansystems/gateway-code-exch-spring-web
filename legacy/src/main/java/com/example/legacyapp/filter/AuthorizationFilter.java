package com.example.legacyapp.filter;

import com.example.legacyapp.service.UserAuthorityService;
import com.example.legacyapp.service.UserAuthorityServiceImpl;
import com.example.legacyapp.util.CookieSigningUtil;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Authorization filter that validates user principal cookie on every request.
 * Java 6 compatible implementation.
 * 
 * <p>This filter checks for the LEGACY_USER_PRINCIPAL cookie on all requests
 * except excluded paths. If the cookie is missing or invalid, redirects to
 * Azure AD login. If valid, loads user authorities from database and stores
 * them in request attributes.</p>
 * 
 * @author Legacy App Integration
 * @version 1.0
 */
public class AuthorizationFilter implements Filter {
    
    private Set<String> excludedPaths;
    private UserAuthorityService userAuthorityService;
    
    private static final String USER_PRINCIPAL_COOKIE_NAME = "LEGACY_USER_PRINCIPAL";
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
        
        // Initialize user authority service
        userAuthorityService = new UserAuthorityServiceImpl();
        
        System.out.println("AuthorizationFilter initialized");
    }
    
    /**
     * Main filter logic - validates user principal cookie
     */
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
        
        // Check for user principal cookie
        String signedPrincipal = getCookieValue(httpRequest, USER_PRINCIPAL_COOKIE_NAME);
        
        if (signedPrincipal == null || signedPrincipal.length() == 0) {
            System.out.println("AuthorizationFilter: No user principal cookie found, redirecting to login");
            redirectToLogin(httpRequest, httpResponse);
            return;
        }
        
        // Verify and extract user principal from signed cookie
        String userPrincipal = CookieSigningUtil.verifyAndExtractCookie(signedPrincipal);
        
        if (userPrincipal == null || userPrincipal.length() == 0) {
            System.err.println("AuthorizationFilter: Invalid or tampered cookie, redirecting to login");
            redirectToLogin(httpRequest, httpResponse);
            return;
        }
        
        System.out.println("AuthorizationFilter: Valid user principal: " + userPrincipal);
        
        // Load user authorities from database
        Collection<String> authorities = null;
        if (userAuthorityService != null) {
            try {
                authorities = userAuthorityService.loadAuthoritiesByUsername(userPrincipal);
                
                // If user not found in database, redirect to unauthorized
                if (authorities == null || authorities.size() == 0) {
                    System.err.println("AuthorizationFilter: User not found in database: " + userPrincipal);
                    redirectToUnauthorized(httpRequest, httpResponse);
                    return;
                }
            } catch (Exception e) {
                System.err.println("AuthorizationFilter: Error loading authorities: " + e.getMessage());
                e.printStackTrace();
                redirectToUnauthorized(httpRequest, httpResponse);
                return;
            }
        }
        
        if (authorities == null) {
            authorities = new ArrayList<String>();
        }
        
        System.out.println("AuthorizationFilter: User authorized with " + authorities.size() + " authorities");
        
        // Store user principal and authorities in request attributes
        httpRequest.setAttribute(REQUEST_USER_PRINCIPAL_KEY, userPrincipal);
        httpRequest.setAttribute(REQUEST_AUTHORITIES_KEY, authorities);
        
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
     * Get cookie value by name
     */
    private String getCookieValue(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (int i = 0; i < cookies.length; i++) {
                if (name.equals(cookies[i].getName())) {
                    return cookies[i].getValue();
                }
            }
        }
        return null;
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
    
    /**
     * Redirect to unauthorized error page
     */
    private void redirectToUnauthorized(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String contextPath = request.getContextPath();
        String unauthorizedUrl = (contextPath != null && contextPath.length() > 0) 
            ? contextPath + "/unauthorized" 
            : "/unauthorized";
        response.sendRedirect(unauthorizedUrl);
    }
}
