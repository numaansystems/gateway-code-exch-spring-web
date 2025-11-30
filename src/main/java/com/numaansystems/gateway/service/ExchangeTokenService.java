package com.numaansystems.gateway. service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent. Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util. concurrent.TimeUnit;

/**
 * Service for creating and validating single-use exchange tokens.
 * 
 * <p>Exchange tokens are short-lived (2 minutes), single-use tokens that
 * contain user information and authorities.  They are used to transfer
 * authentication state from the gateway to the legacy application.</p>
 * 
 * <h2>Token Lifecycle</h2>
 * <ol>
 *   <li>Token created after successful Azure AD authentication</li>
 *   <li>Token passed to legacy app via redirect</li>
 *   <li>Legacy app validates token via backend API call*

cat > src/main/java/com/numaansystems/gateway/service/ExchangeTokenService.java << 'EOF'
package com.numaansystems.gateway. service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent. Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util. concurrent.TimeUnit;

/**
 * Service for creating and validating single-use exchange tokens.
 * 
 * <p>Exchange tokens are short-lived (2 minutes), single-use tokens that
 * contain user information and authorities.  They are used to transfer
 * authentication state from the gateway to the legacy application.</p>
 * 
 * <h2>Token Lifecycle</h2>
 * <ol>
 *   <li>Token created after successful Azure AD authentication</li>
 *   <li>Token passed to legacy app via redirect</li>
 *   <li>Legacy app validates token via backend API call</li>
 *   <li>Token removed from storage (single-use enforcement)</li>
 *   <li>Token auto-expires after TTL if not used</li>
 * </ol>
 * 
 * <h2>Storage</h2>
 * <p>Current implementation uses in-memory ConcurrentHashMap for token storage. 
 * For production with multiple gateway instances, consider using Redis or
 * another distributed cache.</p>
 * 
 * <h2>Security Considerations</h2>
 * <ul>
 *   <li>Tokens are UUID-based (cryptographically random)</li>
 *   <li>Single-use enforcement (removed after validation)</li>
 *   <li>Short TTL (2 minutes, accommodates MFA flow)</li>
 *   <li>Automatic cleanup of expired tokens</li>
 *   <li>No sensitive credentials stored in token</li>
 * </ul>
 * 
 * @author Numaan Systems
 * @version 0. 1.0
 */
@Service
public class ExchangeTokenService {

    private static final Logger logger = LoggerFactory.getLogger(ExchangeTokenService.class);

    @Value("${gateway.exchange-token.ttl-minutes:2}")
    private long ttlMinutes;

    private final ConcurrentHashMap<String, ExchangeTokenData> tokens = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors. newSingleThreadScheduledExecutor();

    /**
     * Creates a new exchange token with user information. 
     * 
     * <p>The token is stored in memory with an expiration timestamp.
     * A scheduled task is created to automatically remove the token after TTL.</p>
     * 
     * @param username the user's username (typically email)
     * @param email the user's email address
     * @param name the user's display name
     * @param authorities the user's authorities/roles
     * @return the generated token string (UUID)
     */
    public String createToken(String username, String email, String name, Set<String> authorities) {
        String token = UUID.randomUUID(). toString();
        long expiresAt = System.currentTimeMillis() + (ttlMinutes * 60 * 1000);

        ExchangeTokenData tokenData = new ExchangeTokenData();
        tokenData.username = username;
        tokenData.email = email;
        tokenData.name = name;
        tokenData. authorities = authorities. toArray(new String[0]);
        tokenData.expiresAt = expiresAt;

        tokens.put(token, tokenData);

        // Schedule automatic token removal after TTL
        scheduler.schedule(() -> {
            ExchangeTokenData removed = tokens.remove(token);
            if (removed != null) {
                logger.info("Expired token removed for user: {}", removed.username);
            }
        }, ttlMinutes, TimeUnit. MINUTES);

        logger.info("Exchange token created for user: {} with {} authorities, expires in {} minutes",
                username, authorities.size(), ttlMinutes);

        return token;
    }

    /**
     * Validates and removes an exchange token (single-use enforcement).
     * 
     * <p>This method:</p>
     * <ol>
     *   <li>Removes the token from storage (single-use)</li>
     *   <li>Checks if token existed</li>
     *   <li>Verifies token has not expired</li>
     *   <li>Returns user data or null if invalid</li>
     * </ol>
     * 
     * <p><strong>Important:</strong> A token can only be validated once. 
     * Subsequent attempts to validate the same token will return null.</p>
     * 
     * @param token the token to validate
     * @return token data if valid, null if invalid or expired
     */
    public ExchangeTokenData validateAndRemoveToken(String token) {
        if (token == null || token.isEmpty()) {
            logger.warn("Token validation failed: empty token");
            return null;
        }

        // Remove token from storage (single-use enforcement)
        ExchangeTokenData tokenData = tokens.remove(token);

        if (tokenData == null) {
            logger.warn("Token validation failed: token not found or already used");
            return null;
        }

        // Check if token has expired
        if (System.currentTimeMillis() > tokenData.expiresAt) {
            logger.warn("Token validation failed: token expired for user {}", tokenData.username);
            return null;
        }

        logger.info("Token validated successfully for user: {} with {} authorities",
                tokenData.username, tokenData.authorities.length);

        return tokenData;
    }

    /**
     * Returns the count of active (not yet validated or expired) tokens.
     * 
     * <p>Useful for monitoring and health checks.</p>
     * 
     * @return the number of active tokens in storage
     */
    public int getActiveTokenCount() {
        return tokens.size();
    }

    /**
     * Data class containing user information from an exchange token.
     * 
     * <p>This class uses public fields for simplicity since it's only used
     * internally within the service layer and returned from validation. </p>
     */
    public static class ExchangeTokenData {
        /** The user's username (typically email address) */
        public String username;
        
        /** The user's email address */
        public String email;
        
        /** The user's display name */
        public String name;
        
        /** Array of user authorities/roles */
        public String[] authorities;
        
        /** Expiration timestamp (milliseconds since epoch) */
        public long expiresAt;
    }
}
