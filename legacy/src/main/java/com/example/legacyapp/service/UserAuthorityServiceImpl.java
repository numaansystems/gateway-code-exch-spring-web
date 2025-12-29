package com.example.legacyapp.service;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;

/**
 * Implementation of UserAuthorityService using JDBC for database access.
 * 
 * <p><strong>Java 6 Compatible:</strong> This implementation uses Java 6 syntax
 * (no try-with-resources, no lambdas) for compatibility with legacy applications.</p>
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
 *     ('admin@example.com', 1, true),  -- ROLE_ADMIN
 *     ('admin@example.com', 4, true),  -- PERMISSION_WRITE
 *     ('user@example.com', 2, true),   -- ROLE_USER
 *     ('user@example.com', 3, true);   -- PERMISSION_READ
 * </pre>
 * 
 * <h2>Database Configuration</h2>
 * <p>Configure via environment variables:</p>
 * <ul>
 *   <li>DB_URL - JDBC connection URL (e.g., jdbc:mysql://localhost:3306/legacy_db)</li>
 *   <li>DB_USERNAME - Database username</li>
 *   <li>DB_PASSWORD - Database password</li>
 *   <li>DB_DRIVER - JDBC driver class (default: com.mysql.cj.jdbc.Driver for MySQL 8+)</li>
 * </ul>
 * 
 * @author Legacy App Integration
 * @version 1.0
 */
public class UserAuthorityServiceImpl implements UserAuthorityService {

    private String dbUrl;
    private String dbUsername;
    private String dbPassword;
    private String dbDriver;
    private boolean configured;

    /**
     * SQL query to load active authorities for a user.
     */
    private static final String LOAD_AUTHORITIES_SQL = 
        "SELECT a.authority_name " +
        "FROM user_authorities ua " +
        "JOIN authorities a ON ua.authority_id = a.id " +
        "WHERE ua.username = ? AND ua.active = true";

    /**
     * Default constructor - loads configuration from environment variables.
     */
    public UserAuthorityServiceImpl() {
        this(System.getenv("DB_URL"),
             System.getenv("DB_USERNAME"),
             System.getenv("DB_PASSWORD"),
             System.getenv("DB_DRIVER"));
    }

    /**
     * Constructor with explicit configuration.
     * 
     * @param dbUrl JDBC connection URL
     * @param dbUsername database username
     * @param dbPassword database password
     * @param dbDriver JDBC driver class name
     */
    public UserAuthorityServiceImpl(String dbUrl, String dbUsername, 
                                   String dbPassword, String dbDriver) {
        this.dbUrl = dbUrl;
        this.dbUsername = dbUsername;
        this.dbPassword = dbPassword;
        // Use newer MySQL driver by default
        // Fallback logic is handled during driver loading (see try-catch block below)
        this.dbDriver = dbDriver != null ? dbDriver : "com.mysql.cj.jdbc.Driver";
        
        // Check if database is configured
        this.configured = (dbUrl != null && dbUrl.length() > 0 &&
                          dbUsername != null && dbUsername.length() > 0 &&
                          dbPassword != null && dbPassword.length() > 0);
        
        if (configured) {
            try {
                // Load JDBC driver
                Class.forName(this.dbDriver);
                System.out.println("UserAuthorityService: Database configured - " + dbUrl);
            } catch (ClassNotFoundException e) {
                System.err.println("UserAuthorityService: JDBC driver not found: " + this.dbDriver);
                System.err.println("UserAuthorityService: Trying deprecated driver com.mysql.jdbc.Driver");
                try {
                    Class.forName("com.mysql.jdbc.Driver");
                    this.dbDriver = "com.mysql.jdbc.Driver";
                    System.out.println("UserAuthorityService: Using deprecated driver - " + this.dbDriver);
                } catch (ClassNotFoundException e2) {
                    System.err.println("UserAuthorityService: No JDBC driver found, disabling database lookup");
                    configured = false;
                }
            }
        } else {
            System.out.println("UserAuthorityService: Database not configured - " +
                             "authority lookup disabled");
        }
    }

    /**
     * Loads active authorities for a user from the database.
     * 
     * <p>Queries the user_authorities and authorities tables to retrieve
     * all active authority names for the specified username.</p>
     * 
     * <p>If database is not configured or query fails, returns empty collection.</p>
     * 
     * @param username the username to load authorities for
     * @return collection of authority strings, empty if none found or error occurs
     */
    public Collection<String> loadAuthoritiesByUsername(String username) {
        if (!configured) {
            System.out.println("UserAuthorityService: Database not configured, " +
                             "returning empty authorities for user: " + username);
            return new ArrayList<String>();
        }
        
        if (username == null || username.length() == 0) {
            System.out.println("UserAuthorityService: Username is null or empty");
            return new ArrayList<String>();
        }
        
        System.out.println("UserAuthorityService: Loading authorities for user: " + username);
        
        Connection conn = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        
        try {
            // Get database connection
            conn = DriverManager.getConnection(dbUrl, dbUsername, dbPassword);
            
            // Prepare and execute query
            stmt = conn.prepareStatement(LOAD_AUTHORITIES_SQL);
            stmt.setString(1, username);
            rs = stmt.executeQuery();
            
            // Collect authorities
            Collection<String> authorities = new ArrayList<String>();
            while (rs.next()) {
                String authority = rs.getString("authority_name");
                authorities.add(authority);
            }
            
            System.out.println("UserAuthorityService: Loaded " + authorities.size() + 
                             " authorities for user: " + username);
            return authorities;
            
        } catch (SQLException e) {
            System.err.println("UserAuthorityService: Failed to load authorities for user " + 
                             username + ": " + e.getMessage());
            e.printStackTrace();
            return new ArrayList<String>();
        } finally {
            // Close resources in reverse order (Java 6 style)
            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException e) {
                    System.err.println("Error closing ResultSet: " + e.getMessage());
                }
            }
            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException e) {
                    System.err.println("Error closing PreparedStatement: " + e.getMessage());
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    System.err.println("Error closing Connection: " + e.getMessage());
                }
            }
        }
    }
}
