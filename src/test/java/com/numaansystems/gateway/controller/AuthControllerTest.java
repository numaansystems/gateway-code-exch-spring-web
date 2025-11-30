package com.numaansystems.gateway.controller;

import com.numaansystems. gateway.service.ExchangeTokenService;
import org.junit.jupiter.api.DisplayName;
import org.junit. jupiter.api.Test;
import org.springframework.beans.factory.annotation. Autowired;
import org.springframework.boot.test.autoconfigure. web.servlet.WebMvcTest;
import org. springframework.boot.test.mock. mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito. Mockito. when;
import static org.springframework. test.web.servlet.request. MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for AuthController.
 * 
 * <p>Tests REST endpoints for authentication initiation, token validation,
 * logout, and health checks.</p>
 */
@WebMvcTest(AuthController. class)
@Import(TestSecurityConfig.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ExchangeTokenService exchangeTokenService;

    @Test
    @DisplayName("Should initiate authentication flow")
    @WithMockUser
    void testInitiateAuth() throws Exception {
        mockMvc.perform(get("/auth/initiate")
                        .param("returnUrl", "http://localhost/dashboard"))
                .andExpect(status().is3xxRedirection())
                . andExpect(redirectedUrl("/oauth2/authorization/azure"));
    }

    @Test
    @DisplayName("Should validate token successfully")
    void testValidateTokenSuccess() throws Exception {
        // Arrange
        ExchangeTokenService.ExchangeTokenData tokenData = new ExchangeTokenService.ExchangeTokenData();
        tokenData.username = "test@example.com";
        tokenData.email = "test@example.com";
        tokenData.name = "Test User";
        tokenData. authorities = new String[]{"ROLE_USER", "ROLE_ADMIN"};
        tokenData.expiresAt = System.currentTimeMillis() + 120000;

        when(exchangeTokenService.validateAndRemoveToken(anyString())). thenReturn(tokenData);

        // Act & Assert
        mockMvc.perform(post("/auth/validate-token")
                        .param("token", "valid-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                . andExpect(jsonPath("$. username").value("test@example.com"))
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.name").value("Test User"))
                .andExpect(jsonPath("$.authorities[0]").value("ROLE_USER"))
                .andExpect(jsonPath("$.authorities[1]").value("ROLE_ADMIN"));
    }

    @Test
    @DisplayName("Should reject invalid token")
    void testValidateTokenFailure() throws Exception {
        // Arrange
        when(exchangeTokenService.validateAndRemoveToken(anyString())).thenReturn(null);

        // Act & Assert
        mockMvc.perform(post("/auth/validate-token")
                        .param("token", "invalid-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false))
                . andExpect(jsonPath("$. error").value("Invalid or expired token"));
    }

    @Test
    @DisplayName("Should return health status")
    void testHealth() throws Exception {
        // Arrange
        when(exchangeTokenService.getActiveTokenCount()).thenReturn(5);

        // Act & Assert
        mockMvc.perform(get("/auth/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.service").value("azure-ad-gateway"))
                .andExpect(jsonPath("$.version").value("1.0.0"))
                .andExpect(jsonPath("$.activeTokens").value(5));
    }

    @Test
    @DisplayName("Should logout and redirect to returnUrl")
    @WithMockUser
    void testLogout() throws Exception {
        mockMvc.perform(get("/auth/logout")
                        .param("returnUrl", "http://localhost/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://localhost/"));
    }

    @Test
    @DisplayName("Should logout without returnUrl and redirect to root")
    @WithMockUser
    void testLogoutWithoutReturnUrl() throws Exception {
        mockMvc. perform(get("/auth/logout"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"));
    }
}
