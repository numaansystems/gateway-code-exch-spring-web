package com. numaansystems.gateway.config;

import com.numaansystems.gateway.service. ExchangeTokenService;
import com.numaansystems.gateway. service.UserAuthorityService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet. http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core. GrantedAuthority;
import org.springframework.security.oauth2. client.authentication.OAuth2AuthenticationToken;
import org.springframework. security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Custom authentication success handler for Azure AD OAuth2 login.
 * 
 * <p>This handler is invoked after successful OAuth2 authentication with Azure AD.
 * It creates a short-lived exchange token and redirects the user back to the
 * originating legacy application. </p>
 * 
 * <h2>Token Exchange Flow</h2>
 * <ol>
 *   <li>User successfully authenticates with Azure AD</li>
 *   <li>Handler extracts user information from OAuth2User</li>
 *   <li>Merges authorities from Azure AD, OAuth2 scopes, and optional database</li>
 *   <li>Creates single-use exchange token (2-minute TTL)</li>
 *   <li>Redirects to legacy app's callback URL with token</li>
 *   <li>Legacy app validates token via backend API call</li>
 * </ol>
 * 
 * <h2>Security Features</h2>
 * <ul>
 *   <li>Domain validation prevents open redirect vulnerabilities</li>
 *   <li>Supports exact domain and subdomain matching</li>
 *   <li>Token contains user info and merged authorities</li>
 *   <li>Comprehensive audit logging</li>
 * </ul>
 * 
 * @author Numaan Systems
 * @version 0.1.0
 */
@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

    private final ExchangeTokenService exchangeTokenService;

    @Autowired(required = false)
    private UserAuthorityService userAuthorityService;

    @Value("${gateway.allowed-redirect-domains}")
    private List<String> allowedRedirectDomains;

    /**
     * Constructor injection of exchange token service.
     * 
     * @param exchangeTokenService service for creating and managing exchange tokens
     */
    public CustomAuthenticationSuccessHandler(ExchangeTokenService exchangeTokenService) {
        this.exchangeTokenService = exchangeTokenService;
    }

    /**
     * Handles successful OAuth2 authentication. 
     * 
     * <p>This method is called by Spring Security after the user successfully
     * authenticates with Azure AD. It extracts user information, creates an
     * exchange token, and redirects back to the legacy application.</p>
     * 
     * @param request the HTTP request
     * @param response the HTTP response
     * @param authentication the authentication object containing OAuth2 user details
     * @throws IOException if redirect fails
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication) throws IOException {
        
        HttpSession session = request.getSession(false);
        String returnUrl = (String) (session != null ? session.getAttribute("returnUrl") : null);

        if (returnUrl != null && ! returnUrl.isEmpty()) {
            // Validate domain to prevent open redirect attacks
            if (!isAllowedDomain(returnUrl)) {
                logger.warn("Unauthorized redirect domain attempted: {}", returnUrl);
                response.sendRedirect("/");
                return;
            }

            // Extract user information from OAuth2 authentication
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            OAuth2User oauth2User = oauthToken.getPrincipal();
            Map<String, Object> attributes = oauth2User.getAttributes();

            // Get username (prefer preferred_username, fallback to email)
            String username = (String) attributes.getOrDefault("preferred_username", attributes.get("email"));
            String email = (String) attributes.get("email");
            String name = (String) attributes.get("name");

            logger.info("Processing authentication success for user: {}", username);

            // Merge authorities from multiple sources
            Set<String> authorities = new HashSet<>();

            // 1. Extract roles from Azure AD token claims
            Object rolesObj = attributes.get("roles");
            if (rolesObj instanceof List) {
                @SuppressWarnings("unchecked")
                List<String> roles = (List<String>) rolesObj;
                authorities.addAll(roles);
                logger.debug("Added {} Azure AD roles for user {}", roles.size(), username);
            }

            // 2.  Add OAuth2 granted authorities (scopes)
            for (GrantedAuthority authority : oauth2User.getAuthorities()) {
                authorities.add(authority. getAuthority());
            }
            logger.debug("Added OAuth2 authorities for user {}", username);

            // 3.  Load additional authorities from database (if service is available)
            if (userAuthorityService != null) {
                try {
                    Collection<String> dbAuthorities = userAuthorityService.loadAuthoritiesByUsername(username);
                    authorities. addAll(dbAuthorities);
                    logger.info("Added {} database authorities for user {}", dbAuthorities.size(), username);
                } catch (Exception e) {
                    logger.warn("Failed to load database authorities for user {}: {}", username, e.getMessage());
                }
            }

            // Create exchange token with user information
            String token = exchangeTokenService.createToken(username, email, name, authorities);
            logger.info("Created exchange token for user {} with {} authorities", username, authorities.size());

            // Build callback URL with token
            String baseUrl = extractBaseUrl(returnUrl);
            String encodedReturnUrl = URLEncoder.encode(returnUrl, StandardCharsets.UTF_8);
            String callbackUrl = baseUrl + "/auth/callback? token=" + token + "&returnUrl=" + encodedReturnUrl;

            // Clean up session
            if (session != null) {
                session.removeAttribute("returnUrl");
            }

            logger.info("Redirecting user {} to callback URL", username);
            response.sendRedirect(callbackUrl);
        } else {
            logger.warn("No returnUrl found in session, redirecting to root");
            response.sendRedirect("/");
        }
    }

    /**
     * Validates that the redirect URL's domain is in the allowed list.
     * 
     * <p>This method prevents open redirect vulnerabilities by ensuring the
     * returnUrl parameter points to a trusted domain.  Supports both exact
     * domain matching and subdomain matching.</p>
     * 
     * @param urlString the URL to validate
     * @return true if the domain is allowed, false otherwise
     */
    private boolean isAllowedDomain(String urlString) {
        try {
            URL url = new URL(urlString);
            String host = url.getHost(). toLowerCase();

            for (String allowedDomain : allowedRedirectDomains) {
                String domain = allowedDomain.toLowerCase();
                
                // Exact match or subdomain match
                if (host.equals(domain) || host.endsWith("." + domain)) {
                    logger.debug("Domain {} matched allowed domain {}", host, domain);
                    return true;
                }
            }

            logger.warn("Domain {} not in allowed list: {}", host, allowedRedirectDomains);
            return false;
        } catch (MalformedURLException e) {
            logger.warn("Malformed URL: {}", urlString, e);
            return false;
        }
    }

    /**
     * Extracts the base URL (protocol, host, port) from a full URL.
     * 
     * @param urlString the full URL
     * @return the base URL (e.g., "https://example.com:8080")
     * @throws MalformedURLException if URL is invalid
     */
    private String extractBaseUrl(String urlString) throws MalformedURLException {
        URL url = new URL(urlString);
        int port = url.getPort();
        String portPart = (port != -1 && port != 80 && port != 443) ? ":" + port : "";
        return url.getProtocol() + "://" + url.getHost() + portPart;
    }
}
