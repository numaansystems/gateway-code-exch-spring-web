package com.numaansystems.gateway.service;

import java.util.Collection;

/**
 * Optional service interface for loading user authorities from a database.
 * 
 * <p>This interface allows the gateway to supplement Azure AD authorities
 * with application-specific authorities stored in a local database. 
 * The implementation is optional - the gateway works without it.</p>
 * 
 * <h2>Usage</h2>
 * <p>To enable database authority lookup:</p>
 * <ol>
 *   <li>Uncomment @Service annotation in UserAuthorityServiceImpl</li>
 *   <li>Configure database connection in application.yml</li>
 *   <li>Create required database tables (see UserAuthorityServiceImpl)</li>
 *   <li>Populate tables with user authorities</li>
 * </ol>
 * 
 * <h2>Authority Merging</h2>
 * <p>Authorities from multiple sources are merged:</p>
 * <ul>
 *   <li>Azure AD roles (from token claims)</li>
 *   <li>OAuth2 scopes (from OAuth2User authorities)</li>
 *   <li>Database authorities (from this service)</li>
 * </ul>
 * 
 * <h2>Injection</h2>
 * <p>This service is autowired with @Autowired(required=false) in
 * CustomAuthenticationSuccessHandler, so the application works whether
 * or not an implementation is available.</p>
 * 
 * @author Numaan Systems
 * @version 0.1.0
 */
public interface UserAuthorityService {

    /**
     * Loads authorities for a user from the database.
     * 
     * <p>Returns a collection of authority strings (e.g., "ROLE_ADMIN",
     * "PERMISSION_READ", "FEATURE_REPORTS").  These will be merged with
     * authorities from Azure AD and OAuth2 scopes.</p>
     * 
     * @param username the username to load authorities for (typically email)
     * @return collection of authority strings, empty if none found
     * @throws RuntimeException if database error occurs (will be caught and logged)
     */
    Collection<String> loadAuthoritiesByUsername(String username);
}
