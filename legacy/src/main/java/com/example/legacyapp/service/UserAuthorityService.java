package com.example.legacyapp.service;

import java.util.Collection;

/**
 * Optional service interface for loading user authorities from a database.
 * 
 * <p>This interface allows the legacy application to supplement Azure AD authorities
 * with application-specific authorities stored in a local database. 
 * The implementation is optional - the application works without it.</p>
 * 
 * <h2>Usage</h2>
 * <p>To enable database authority lookup:</p>
 * <ol>
 *   <li>Configure database connection via environment variables or init params</li>
 *   <li>Create required database tables (see UserAuthorityServiceImpl)</li>
 *   <li>Populate tables with user authorities</li>
 * </ol>
 * 
 * <h2>Authority Merging</h2>
 * <p>Authorities from multiple sources are merged:</p>
 * <ul>
 *   <li>Azure AD roles (from token claims)</li>
 *   <li>Database authorities (from this service)</li>
 * </ul>
 * 
 * @author Legacy App Integration
 * @version 1.0
 */
public interface UserAuthorityService {

    /**
     * Loads authorities for a user from the database.
     * 
     * <p>Returns a collection of authority strings (e.g., "ROLE_ADMIN",
     * "PERMISSION_READ", "FEATURE_REPORTS").  These will be merged with
     * authorities from Azure AD.</p>
     * 
     * @param username the username to load authorities for (typically email or userPrincipalName)
     * @return collection of authority strings, empty if none found
     * @throws RuntimeException if database error occurs (will be caught and logged)
     */
    Collection<String> loadAuthoritiesByUsername(String username);
}
