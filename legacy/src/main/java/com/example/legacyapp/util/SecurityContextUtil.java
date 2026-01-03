package com.example.legacyapp.util;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Utility to integrate HttpSession authentication with Spring SecurityContextHolder.
 * Java 6 compatible implementation.
 * 
 * <p>This utility bridges the gap between session-based authentication and Spring Security's
 * SecurityContextHolder, allowing legacy applications to leverage Spring Security features
 * while using simple session-based authentication.</p>
 * 
 * @author Legacy App Integration
 * @version 1.0
 */
public class SecurityContextUtil {
    
    // Session attribute keys - must match AzureADCallbackFilter and AuthorizationFilter
    private static final String SESSION_AUTHENTICATED_KEY = "authenticated";
    private static final String SESSION_USER_PRINCIPAL_KEY = "userPrincipal";
    private static final String SESSION_AUTHORITIES_KEY = "oauth2_authorities";
    
    /**
     * Populate SecurityContextHolder from HttpSession attributes.
     * 
     * <p>Reads authentication state from session and creates a Spring Security
     * Authentication object. If session is null or not authenticated, clears
     * the SecurityContextHolder.</p>
     * 
     * @param session the HTTP session containing authentication state
     */
    @SuppressWarnings("unchecked")
    public static void populateSecurityContext(HttpSession session) {
        if (session == null) {
            SecurityContextHolder.clearContext();
            return;
        }
        
        Boolean authenticated = (Boolean) session.getAttribute(SESSION_AUTHENTICATED_KEY);
        if (authenticated == null || !authenticated) {
            SecurityContextHolder.clearContext();
            return;
        }
        
        String userPrincipal = (String) session.getAttribute(SESSION_USER_PRINCIPAL_KEY);
        Collection authStrings = (Collection) session.getAttribute(SESSION_AUTHORITIES_KEY);
        
        if (userPrincipal == null) {
            SecurityContextHolder.clearContext();
            return;
        }
        
        // Convert authority strings to GrantedAuthority objects
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        if (authStrings != null) {
            for (Object authObj : authStrings) {
                if (authObj instanceof String) {
                    authorities.add(new SimpleGrantedAuthority((String) authObj));
                }
            }
        }
        
        // Create authentication token
        Authentication authentication = new UsernamePasswordAuthenticationToken(
            userPrincipal, null, authorities);
        
        // Set in SecurityContextHolder
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
    
    /**
     * Get current authenticated user from SecurityContextHolder.
     * 
     * @return the username of the current authenticated user, or null if not authenticated
     */
    public static String getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            return auth.getName();
        }
        return null;
    }
}
