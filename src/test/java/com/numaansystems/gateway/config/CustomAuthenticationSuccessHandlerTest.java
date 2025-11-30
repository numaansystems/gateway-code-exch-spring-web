package com.numaansystems.gateway.config;

import com.numaansystems.gateway.service.ExchangeTokenService;
import com.numaansystems.gateway. service.UserAuthorityService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet. http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter. api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org. junit.jupiter.api.Test;
import org.junit.jupiter. api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito. junit.jupiter.MockitoExtension;
import org.springframework. security.core. GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org. springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2. core.user.OAuth2User;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito. Mockito.*;

/**
 * Unit tests for CustomAuthenticationSuccessHandler.
 * 
 * <p>Tests OAuth2 authentication success handling, domain validation,
 * authority merging, and redirect behavior.</p>
 */
@ExtendWith(MockitoExtension.class)
class CustomAuthenticationSuccessHandlerTest {

    @Mock
    private ExchangeTokenService exchangeTokenService;

    @Mock
    private UserAuthorityService userAuthorityService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    private CustomAuthenticationSuccessHandler successHandler;

    @BeforeEach
    void setUp() {
        successHandler = new CustomAuthenticationSuccessHandler(exchangeTokenService);
        ReflectionTestUtils. setField(successHandler, "userAuthorityService", userAuthorityService);
        ReflectionTestUtils.setField(successHandler, "allowedRedirectDomains", 
                List.of("app.example.com", "localhost"));
    }

    @Test
    @DisplayName("Should redirect to returnUrl with token on successful authentication")
    void testSuccessfulAuthenticationWithReturnUrl() throws Exception {
        // Arrange
        String returnUrl = "http://app.example.com/dashboard";
        String token = "test-token-123";

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("preferred_username", "test@example. com");
        attributes.put("email", "test@example.com");
        attributes.put("name", "Test User");
        attributes. put("roles", List.of("ROLE_AZURE_USER"));

        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("SCOPE_openid"));

        OAuth2User oauth2User = new DefaultOAuth2User(authorities, attributes, "preferred_username");
        OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(oauth2User, authorities, "azure");

        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("returnUrl")).thenReturn(returnUrl);
        when(exchangeTokenService.createToken(anyString(), anyString(), anyString(), anySet())).thenReturn(token);
        when(userAuthorityService.loadAuthoritiesByUsername(anyString())). thenReturn(List.of("ROLE_DB_ADMIN"));

        // Act
        successHandler.onAuthenticationSuccess(request, response, authentication);

        // Assert
        verify(session).removeAttribute("returnUrl");
        verify(response).sendRedirect(contains("/auth/callback"));
        verify(response).sendRedirect(contains("token=" + token));
        verify(exchangeTokenService).createToken(
                eq("test@example.com"),
                eq("test@example. com"),
                eq("Test User"),
                anySet()
        );
    }

    @Test
    @DisplayName("Should redirect to root when no returnUrl")
    void testSuccessfulAuthenticationWithoutReturnUrl() throws Exception {
        // Arrange
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("email", "test@example.com");
        attributes.put("name", "Test User");

        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("SCOPE_openid"));

        OAuth2User oauth2User = new DefaultOAuth2User(authorities, attributes, "email");
        OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(oauth2User, authorities, "azure");

        when(request.getSession(false)).thenReturn(session);
        when(session. getAttribute("returnUrl")).thenReturn(null);

        // Act
        successHandler. onAuthenticationSuccess(request, response, authentication);

        // Assert
        verify(response).sendRedirect("/");
        verify(exchangeTokenService, never()).createToken(anyString(), anyString(), anyString(), anySet());
    }

    @Test
    @DisplayName("Should reject unauthorized domain")
    void testUnauthorizedDomain() throws Exception {
        // Arrange
        String returnUrl = "http://malicious.com/dashboard";

        Map<String, Object> attributes = new HashMap<>();
        attributes. put("preferred_username", "test@example.com");
        attributes.put("email", "test@example.com");
        attributes. put("name", "Test User");

        Set<GrantedAuthority> authorities = new HashSet<>();
        OAuth2User oauth2User = new DefaultOAuth2User(authorities, attributes, "preferred_username");
        OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(oauth2User, authorities, "azure");

        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("returnUrl")).thenReturn(returnUrl);

        // Act
        successHandler.onAuthenticationSuccess(request, response, authentication);

        // Assert
        verify(response).sendRedirect("/");
        verify(exchangeTokenService, never()).createToken(anyString(), anyString(), anyString(), anySet());
    }

    @Test
    @DisplayName("Should accept subdomain of allowed domain")
    void testSubdomainAllowed() throws Exception {
        // Arrange
        String returnUrl = "http://admin.app.example.com/dashboard";
        String token = "test-token-456";

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("preferred_username", "admin@example.com");
        attributes.put("email", "admin@example.com");
        attributes. put("name", "Admin User");

        Set<GrantedAuthority> authorities = new HashSet<>();
        OAuth2User oauth2User = new DefaultOAuth2User(authorities, attributes, "preferred_username");
        OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(oauth2User, authorities, "azure");

        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("returnUrl")).thenReturn(returnUrl);
        when(exchangeTokenService.createToken(anyString(), anyString(), anyString(), anySet())).thenReturn(token);
        when(userAuthorityService.loadAuthoritiesByUsername(anyString())).thenReturn(Collections.emptyList());

        // Act
        successHandler.onAuthenticationSuccess(request, response, authentication);

        // Assert
        verify(response).sendRedirect(contains("/auth/callback"));
        verify(exchangeTokenService).createToken(anyString(), anyString(), anyString(), anySet());
    }

    @Test
    @DisplayName("Should merge authorities from multiple sources")
    void testAuthorityMerging() throws Exception {
        // Arrange
        String returnUrl = "http://app.example.com/dashboard";
        String token = "test-token-789";

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("preferred_username", "test@example.com");
        attributes.put("email", "test@example.com");
        attributes.put("name", "Test User");
        attributes.put("roles", List.of("ROLE_AZURE_USER", "ROLE_AZURE_ADMIN"));

        Set<GrantedAuthority> oauthAuthorities = new HashSet<>();
        oauthAuthorities.add(new SimpleGrantedAuthority("SCOPE_openid"));
        oauthAuthorities. add(new SimpleGrantedAuthority("SCOPE_profile"));

        OAuth2User oauth2User = new DefaultOAuth2User(oauthAuthorities, attributes, "preferred_username");
        OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(oauth2User, oauthAuthorities, "azure");

        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("returnUrl")).thenReturn(returnUrl);
        when(exchangeTokenService.createToken(anyString(), anyString(), anyString(), anySet())).thenReturn(token);
        when(userAuthorityService.loadAuthoritiesByUsername(anyString()))
                .thenReturn(List.of("ROLE_DB_ADMIN", "PERMISSION_READ"));

        // Act
        successHandler.onAuthenticationSuccess(request, response, authentication);

        // Assert
        verify(exchangeTokenService).createToken(
                eq("test@example.com"),
                eq("test@example.com"),
                eq("Test User"),
                argThat(auths -> 
                    auths.contains("ROLE_AZURE_USER") &&
                    auths.contains("ROLE_AZURE_ADMIN") &&
                    auths. contains("SCOPE_openid") &&
                    auths.contains("SCOPE_profile") &&
                    auths.contains("ROLE_DB_ADMIN") &&
                    auths.contains("PERMISSION_READ")
                )
        );
    }

    @Test
    @DisplayName("Should use email when preferred_username is not available")
    void testFallbackToEmail() throws Exception {
        // Arrange
        String returnUrl = "http://app. example.com/dashboard";
        String token = "test-token-999";

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("email", "test@example.com");
        attributes.put("name", "Test User");
        // No preferred_username

        Set<GrantedAuthority> authorities = new HashSet<>();
        OAuth2User oauth2User = new DefaultOAuth2User(authorities, attributes, "email");
        OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(oauth2User, authorities, "azure");

        when(request. getSession(false)).thenReturn(session);
        when(session.getAttribute("returnUrl")).thenReturn(returnUrl);
        when(exchangeTokenService.createToken(anyString(), anyString(), anyString(), anySet())).thenReturn(token);
        when(userAuthorityService.loadAuthoritiesByUsername(anyString())).thenReturn(Collections.emptyList());

        // Act
        successHandler.onAuthenticationSuccess(request, response, authentication);

        // Assert
        verify(exchangeTokenService).createToken(
                eq("test@example.com"),
                eq("test@example.com"),
                eq("Test User"),
                anySet()
        );
    }
}
