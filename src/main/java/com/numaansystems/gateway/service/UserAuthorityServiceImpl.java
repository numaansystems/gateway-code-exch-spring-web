package com. numaansystems.gateway.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
// import org.springframework.stereotype.Service;

import java.util. Collection;
import java.util. Collections;

/**
 * Implementation of UserAuthorityService using JDBC for database access.
 * 
 * <p><strong>DISABLED BY DEFAULT:</strong> The @Service annotation is commented out. 
 * To enable database authority lookup, uncomment the @Service annotation and
 * configure database connection in application.yml.</p>
 * 
 * <h2>Database Schema</h2>
 * <p>This implementation requires two tables:</p>
 * 
 * <h3>authorities table</h3>
 * <pre>
 * CREATE TABLE authorities (
 *     id BIGINT PRIMARY KEY AUTO_INCREMENT,
 *     authority_name VARCHAR(100) NOT NULL UNIQUE,
 *     description VARCHAR(255),
 *     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 *     INDEX idx_authority_name (authority_name)
 * );
 * </pre>
 * 
 * <h3>user_authorities table</h3>
 * <pre>
 * CREATE TABLE user_authorities (
 *     id BIGINT PRIMARY KEY AUTO_INCREMENT,
 *     username VARCHAR(255) NOT NULL,
 *     authority_id BIGINT NOT NULL,
 *     active BOOLEAN DEFAULT true,
 *     granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 *     FOREIGN KEY (authority_id) REFERENCES authorities(id) ON DELETE CASCADE,
 *     UNIQUE KEY unique_user_authority (username, authority_id),
 *     INDEX idx_username (username),
 *     INDEX idx_active (active)
 * );
 * </pre>
 * 
 * <h2>Sample Data</h2>
 * <pre>
 * -- Insert sample authorities
 * INSERT INTO authorities (authority_name, description) VALUES
 *     ('ROLE_ADMIN', 'Administrator role with full access'),
 *     ('ROLE_USER', 'Standard user role'),
 *     ('PERMISSION_READ', 'Read permission for resources'),
 *     ('PERMISSION_WRITE', 'Write permission for resources'),
 *     ('FEATURE_REPORTS', 'Access to reporting features');
 * 
 * -- Assign authorities to users
 * INSERT INTO user_authorities (username, authority_id, active) VALUES
 *     ('admin@numaansystems.com', 1, true),  -- ROLE_ADMIN
 *     ('admin@numaansystems.com', 4, true),  -- PERMISSION_WRITE
 *     ('user@numaansystems.com', 2, true),   -- ROLE_USER
 *     ('user@numaansystems.com', 3, true);   -- PERMISSION_READ
 * </pre>
 * 
 * <h2>Database Configuration</h2>
 * <p>Add to application.yml:</p>
 * <pre>
 * spring:
 *   datasource:
 *     url: jdbc:mysql://localhost:3306/gateway_db
 *     username: gateway_user
 *     password: ${DB_PASSWORD}
 *     driver-class-name: com. mysql.cj.jdbc.Driver
 *   jpa:
 *     hibernate:
 *       ddl-auto: validate
 * </pre>
 * 
 * @author Numaan Systems
 * @version 0.1.0
 */
// @Service  // UNCOMMENT THIS LINE TO ENABLE DATABASE AUTHORITY LOOKUP
public class UserAuthorityServiceImpl implements UserAuthorityService {

    private static final Logger logger = LoggerFactory.getLogger(UserAuthorityServiceImpl.class);

    private final JdbcTemplate jdbcTemplate;

    /**
     * Constructor injection of JdbcTemplate.
     * 
     * @param jdbcTemplate Spring JDBC template for database access
     */
    public UserAuthorityServiceImpl(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Loads active authorities for a user from the database. 
     * 
     * <p>Queries the user_authorities and authorities tables to retrieve
     * all active authority names for the specified username.</p>
     * 
     * @param username the username to load authorities for
     * @return collection of authority strings, empty if none found or error occurs
     */
    @Override
    public Collection<String> loadAuthoritiesByUsername(String username) {
        logger.debug("Loading database authorities for user: {}", username);

        String sql = """
            SELECT a.authority_name 
            FROM user_authorities ua
            JOIN authorities a ON ua.authority_id = a.id
            WHERE ua.username = ?  AND ua.active = true
            """;

        try {
            Collection<String> authorities = jdbcTemplate.queryForList(sql, String.class, username);
            logger.info("Loaded {} database authorities for user: {}", authorities. size(), username);
            return authorities;
        } catch (Exception e) {
            logger.error("Failed to load database authorities for user {}: {}", username, e.getMessage(), e);
            return Collections.emptyList();
        }
    }
}
