package com. numaansystems.gateway.service;

import org.junit.jupiter.api.BeforeEach;
import org. junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.HashSet;
import java.util. Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ExchangeTokenService.
 * 
 * <p>Tests token creation, validation, single-use enforcement,
 * expiration, and active token tracking.</p>
 */
class ExchangeTokenServiceTest {

    private ExchangeTokenService tokenService;

    @BeforeEach
    void setUp() {
        tokenService = new ExchangeTokenService();
        // Set TTL to 2 minutes for testing
        ReflectionTestUtils.setField(tokenService, "ttlMinutes", 2L);
    }

    @Test
    @DisplayName("Should create token with valid user information")
    void testCreateToken() {
        // Arrange
        String username = "test@example.com";
        String email = "test@example.com";
        String name = "Test User";
        Set<String> authorities = new HashSet<>(Set.of("ROLE_USER", "ROLE_ADMIN"));

        // Act
        String token = tokenService.createToken(username, email, name, authorities);

        // Assert
        assertNotNull(token, "Token should not be null");
        assertFalse(token.isEmpty(), "Token should not be empty");
        assertEquals(1, tokenService.getActiveTokenCount(), "Should have one active token");
    }

    @Test
    @DisplayName("Should validate token successfully")
    void testValidateToken() {
        // Arrange
        String username = "test@example.com";
        String email = "test@example.com";
        String name = "Test User";
        Set<String> authorities = new HashSet<>(Set.of("ROLE_USER"));
        String token = tokenService.createToken(username, email, name, authorities);

        // Act
        ExchangeTokenService.ExchangeTokenData tokenData = tokenService.validateAndRemoveToken(token);

        // Assert
        assertNotNull(tokenData, "Token data should not be null");
        assertEquals(username, tokenData.username, "Username should match");
        assertEquals(email, tokenData.email, "Email should match");
        assertEquals(name, tokenData.name, "Name should match");
        assertEquals(1, tokenData.authorities.length, "Should have one authority");
        assertEquals("ROLE_USER", tokenData.authorities[0], "Authority should match");
    }

    @Test
    @DisplayName("Should enforce single-use token")
    void testSingleUseToken() {
        // Arrange
        String username = "test@example.com";
        String email = "test@example.com";
        String name = "Test User";
        Set<String> authorities = new HashSet<>(Set.of("ROLE_USER"));
        String token = tokenService.createToken(username, email, name, authorities);

        // Act
        ExchangeTokenService.ExchangeTokenData firstValidation = tokenService.validateAndRemoveToken(token);
        ExchangeTokenService.ExchangeTokenData secondValidation = tokenService.validateAndRemoveToken(token);

        // Assert
        assertNotNull(firstValidation, "First validation should succeed");
        assertNull(secondValidation, "Second validation should fail (single-use)");
        assertEquals(0, tokenService.getActiveTokenCount(), "Should have no active tokens after validation");
    }

    @Test
    @DisplayName("Should return null for invalid token")
    void testInvalidToken() {
        // Act
        ExchangeTokenService.ExchangeTokenData tokenData = tokenService.validateAndRemoveToken("invalid-token");

        // Assert
        assertNull(tokenData, "Should return null for invalid token");
    }

    @Test
    @DisplayName("Should return null for null token")
    void testNullToken() {
        // Act
        ExchangeTokenService.ExchangeTokenData tokenData = tokenService.validateAndRemoveToken(null);

        // Assert
        assertNull(tokenData, "Should return null for null token");
    }

    @Test
    @DisplayName("Should return null for empty token")
    void testEmptyToken() {
        // Act
        ExchangeTokenService.ExchangeTokenData tokenData = tokenService.validateAndRemoveToken("");

        // Assert
        assertNull(tokenData, "Should return null for empty token");
    }

    @Test
    @DisplayName("Should handle multiple authorities")
    void testMultipleAuthorities() {
        // Arrange
        String username = "test@example.com";
        String email = "test@example.com";
        String name = "Test User";
        Set<String> authorities = new HashSet<>(Set.of("ROLE_USER", "ROLE_ADMIN", "PERMISSION_READ", "PERMISSION_WRITE"));
        String token = tokenService.createToken(username, email, name, authorities);

        // Act
        ExchangeTokenService.ExchangeTokenData tokenData = tokenService.validateAndRemoveToken(token);

        // Assert
        assertNotNull(tokenData, "Token data should not be null");
        assertEquals(4, tokenData.authorities. length, "Should have four authorities");
    }

    @Test
    @DisplayName("Should handle empty authorities")
    void testEmptyAuthorities() {
        // Arrange
        String username = "test@example.com";
        String email = "test@example.com";
        String name = "Test User";
        Set<String> authorities = new HashSet<>();
        String token = tokenService. createToken(username, email, name, authorities);

        // Act
        ExchangeTokenService.ExchangeTokenData tokenData = tokenService.validateAndRemoveToken(token);

        // Assert
        assertNotNull(tokenData, "Token data should not be null");
        assertEquals(0, tokenData. authorities.length, "Should have no authorities");
    }

    @Test
    @DisplayName("Should track active token count correctly")
    void testActiveTokenCount() {
        // Arrange
        String username = "test@example.com";
        String email = "test@example.com";
        String name = "Test User";
        Set<String> authorities = new HashSet<>(Set.of("ROLE_USER"));

        // Act & Assert
        assertEquals(0, tokenService.getActiveTokenCount(), "Should start with no tokens");

        String token1 = tokenService.createToken(username, email, name, authorities);
        assertEquals(1, tokenService.getActiveTokenCount(), "Should have one active token");

        String token2 = tokenService.createToken(username, email, name, authorities);
        assertEquals(2, tokenService.getActiveTokenCount(), "Should have two active tokens");

        tokenService.validateAndRemoveToken(token1);
        assertEquals(1, tokenService.getActiveTokenCount(), "Should have one active token after first validation");

        tokenService.validateAndRemoveToken(token2);
        assertEquals(0, tokenService.getActiveTokenCount(), "Should have no active tokens after both validations");
    }

    @Test
    @DisplayName("Should create unique tokens")
    void testUniqueTokens() {
        // Arrange
        String username = "test@example.com";
        String email = "test@example.com";
        String name = "Test User";
        Set<String> authorities = new HashSet<>(Set. of("ROLE_USER"));

        // Act
        String token1 = tokenService.createToken(username, email, name, authorities);
        String token2 = tokenService.createToken(username, email, name, authorities);

        // Assert
        assertNotEquals(token1, token2, "Tokens should be unique");
    }

    @Test
    @DisplayName("Should create token with expiration timestamp in the future")
    void testTokenExpirationTimestamp() {
        // Arrange
        long beforeCreation = System.currentTimeMillis();
        String username = "test@example.com";
        String email = "test@example.com";
        String name = "Test User";
        Set<String> authorities = new HashSet<>(Set. of("ROLE_USER"));

        // Act
        String token = tokenService.createToken(username, email, name, authorities);
        ExchangeTokenService.ExchangeTokenData tokenData = tokenService. validateAndRemoveToken(token);

        // Assert
        assertNotNull(tokenData, "Token data should not be null");
        assertTrue(tokenData.expiresAt > beforeCreation, "Expiration should be in the future");
        
        long expectedExpiration = beforeCreation + (2 * 60 * 1000); // 2 minutes
        assertTrue(Math.abs(tokenData.expiresAt - expectedExpiration) < 1000, 
                   "Expiration should be approximately 2 minutes from creation");
    }
}
