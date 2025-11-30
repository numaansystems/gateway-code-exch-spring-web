package com.numaansystems.gateway;

import com.numaansystems.gateway. service.ExchangeTokenService;
import org.junit.jupiter.api.DisplayName;
import org.junit. jupiter.api.Test;
import org.springframework.beans.factory. annotation.Autowired;
import org.springframework.boot.test. context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import java.util. HashSet;
import java.util. Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for the Gateway application.
 * 
 * <p>These tests verify that the Spring application context loads correctly
 * and that key beans are available and functional.</p>
 */
@SpringBootTest
class GatewayApplicationTests {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private ExchangeTokenService exchangeTokenService;

    @Test
    @DisplayName("Should load application context")
    void contextLoads() {
        assertNotNull(applicationContext, "Application context should not be null");
    }

    @Test
    @DisplayName("Should have ExchangeTokenService bean")
    void testExchangeTokenServiceBean() {
        assertNotNull(exchangeTokenService, "ExchangeTokenService bean should be available");
    }

    @Test
    @DisplayName("Should create and validate token in integrated environment")
    void testTokenServiceIntegration() {
        // Arrange
        String username = "integration@example.com";
        String email = "integration@example.com";
        String name = "Integration Test User";
        Set<String> authorities = new HashSet<>(Set.of("ROLE_INTEGRATION_TEST"));

        // Act - Create token
        String token = exchangeTokenService.createToken(username, email, name, authorities);

        // Assert - Token created
        assertNotNull(token, "Token should be created");
        assertFalse(token.isEmpty(), "Token should not be empty");

        // Act - Validate token
        ExchangeTokenService.ExchangeTokenData tokenData = exchangeTokenService.validateAndRemoveToken(token);

        // Assert - Token data retrieved
        assertNotNull(tokenData, "Token data should be retrieved");
        assertEquals(username, tokenData.username, "Username should match");
        assertEquals(email, tokenData.email, "Email should match");
        assertEquals(name, tokenData.name, "Name should match");
        assertEquals(1, tokenData.authorities.length, "Should have one authority");
        assertEquals("ROLE_INTEGRATION_TEST", tokenData.authorities[0], "Authority should match");
    }
}
