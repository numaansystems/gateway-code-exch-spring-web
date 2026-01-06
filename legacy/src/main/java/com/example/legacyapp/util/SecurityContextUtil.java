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
 * <p><strong>Performance Characteristics:</strong> This utility is designed for high-performance
 * request handling. All methods in this class ONLY read from existing HttpSession attributes
 * and do NOT make any database calls or external service calls.</p>
 * 
 * <p>This utility bridges the gap between session-based authentication and Spring Security's
 * SecurityContextHolder, allowing legacy applications to leverage Spring Security features
 * while using simple session-based authentication.</p>
 * 
 * <p><strong>Architecture Note:</strong> User authorities are loaded from the database once
 * during login by AzureADCallbackFilter and stored in the session. This utility simply reads
 * those pre-loaded authorities from the session on each request, ensuring fast request processing.</p>
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
     * <p><strong>Performance:</strong> This method ONLY reads from the provided HttpSession
     * and does NOT make any database calls or external service calls. It is designed to be
     * called on every request with minimal overhead.</p>
     * 
     * <p>Reads authentication state from session and creates a Spring Security
     * Authentication object. If session is null or not authenticated, clears
     * the SecurityContextHolder.</p>
     * 
     * <p><strong>Note:</strong> User authorities should already be loaded and stored in
     * the session by AzureADCallbackFilter during login. This method simply reads those
     * pre-loaded authorities from the session.</p>
     * 
     * @param session the HTTP session containing authentication state (authorities pre-loaded)
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
