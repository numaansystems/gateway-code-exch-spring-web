package com.numaansystems.gateway.config;

import com.numaansystems.gateway. service.ExchangeTokenService;
import com.numaansystems.gateway. service.UserAuthorityService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation. Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core. GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler. class);

    private final ExchangeTokenService exchangeTokenService;

    @Autowired(required = false)
    private UserAuthorityService userAuthorityService;

    @Value("${gateway.allowed-redirect-domains}")
    private List<String> allowedRedirectDomains;

    public CustomAuthenticationSuccessHandler(ExchangeTokenService exchangeTokenService) {
        this.exchangeTokenService = exchangeTokenService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication) throws IOException {
        
        logger.info("==================== AUTH SUCCESS ====================");
        
        HttpSession session = request.getSession(false);
        
        if (session == null) {
            logger.error("No session found in success handler!");
            response.sendRedirect("/");
            return;
        }
        
        String returnUrl = (String) session.getAttribute("returnUrl");
        String finalReturnUrl = (String) session.getAttribute("finalReturnUrl");

        logger.info("Session ID: {}", session.getId());
        logger.info("ReturnUrl (callback): {}", returnUrl);
        logger.info("FinalReturnUrl (destination): {}", finalReturnUrl);
        logger.info("Authentication type: {}", authentication.getClass(). getSimpleName());
        logger.info("Authentication principal: {}", authentication.getName());

        if (returnUrl == null || returnUrl.isEmpty()) {
            logger.warn("No returnUrl found in session, redirecting to root");
            response.sendRedirect("/");
            return;
        }

        // Validate domain
        if (!isAllowedDomain(returnUrl)) {
            logger.warn("Unauthorized redirect domain attempted: {}", returnUrl);
            response.sendRedirect("/");
            return;
        }

        // Extract user information from OAuth2 authentication
        if (!(authentication instanceof OAuth2AuthenticationToken)) {
            logger.error("Authentication is not OAuth2AuthenticationToken: {}", authentication.getClass());
            response.sendRedirect("/");
            return;
        }

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oauth2User = oauthToken. getPrincipal();
        
        if (oauth2User == null) {
            logger.error("OAuth2User is null!");
            response.sendRedirect("/");
            return;
        }
        
        Map<String, Object> attributes = oauth2User.getAttributes();

        // Extract username with multiple fallbacks
        String username = extractUsername(attributes);
        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");

        if (username == null || username.isEmpty()) {
            logger.error("Could not extract username from OAuth2 attributes!");
            logger.error("Available attributes: {}", attributes);
            response.sendRedirect("/?error=no_username");
            return;
        }

        logger.info("Processing authentication success for user: {}", username);
        logger.info("  Email: {}", email);
        logger.info("  Name: {}", name);

        // Merge authorities from multiple sources
        Set<String> authorities = new HashSet<>();

        // 1. Extract roles from Azure AD token claims
        Object rolesObj = attributes.get("roles");
        if (rolesObj instanceof List) {
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) rolesObj;
            authorities.addAll(roles);
            logger.info("Added {} Azure AD roles", roles.size());
        }

        // 2. Add OAuth2 granted authorities (scopes)
        for (GrantedAuthority authority : oauth2User.getAuthorities()) {
            authorities.add(authority. getAuthority());
        }
        logger.info("Total authorities from OAuth2: {}", authorities.size());

        // 3. Load additional authorities from database (if service is available)
        if (userAuthorityService != null) {
            try {
                Collection<String> dbAuthorities = userAuthorityService.loadAuthoritiesByUsername(username);
                authorities.addAll(dbAuthorities);
                logger.info("Added {} database authorities", dbAuthorities.size());
            } catch (Exception e) {
                logger.warn("Failed to load database authorities: {}", e.getMessage());
            }
        }

        logger.info("Total merged authorities: {}", authorities.size());

        // Create exchange token with user information
        String token = exchangeTokenService.createToken(username, email, name, authorities);
        logger.info("Created exchange token for user {}: {}", username, token. substring(0, Math.min(10, token.length())) + "...");

        // Build callback URL with token
        String separator = returnUrl.contains("?") ? "&" : "?";
        StringBuilder callbackUrl = new StringBuilder(returnUrl);
        callbackUrl. append(separator).append("token=").append(token);
        
        // Add finalReturnUrl if present
        if (finalReturnUrl != null && !finalReturnUrl.isEmpty()) {
            callbackUrl.append("&returnUrl=").append(URLEncoder. encode(finalReturnUrl, StandardCharsets.UTF_8));
        }

        // Clean up session
        session.removeAttribute("returnUrl");
        session. removeAttribute("finalReturnUrl");
        session.removeAttribute("forceReauth");

        logger.info("Redirecting user {} to: {}", username, callbackUrl.toString());
        logger.info("=======================================================");
        
        response.sendRedirect(callbackUrl.toString());
    }

    /**
     * Extract username from OAuth2 attributes with multiple fallbacks
     */
    private String extractUsername(Map<String, Object> attributes) {
        logger.info("Extracting username from attributes:");
        
        // Log all attributes for debugging
        for (Map.Entry<String, Object> entry : attributes.entrySet()) {
            Object value = entry.getValue();
            logger.info("  {}: {} ({})", 
                       entry.getKey(), 
                       value, 
                       value != null ? value.getClass().getSimpleName() : "null");
        }
        
        // Try different attribute names in order of preference
        String[] usernameAttributes = {
            "preferred_username",  // Standard OIDC claim
            "unique_name",         // Azure AD v1. 0 token (YOUR CASE!)
            "upn",                 // User Principal Name
            "email",               // Email address
            "sub",                 // Subject (unique user ID)
            "oid"                  // Object ID (Azure AD user ID)
        };
        
        for (String attr : usernameAttributes) {
            Object value = attributes.get(attr);
            if (value != null && ! value.toString().trim().isEmpty()) {
                logger. info("✓ Using '{}' attribute for username: {}", attr, value);
                return value.toString();
            }
        }
        
        logger.error("✗ Could not find username in any known attribute");
        return null;
    }

    /**
     * Validates that the redirect URL's domain is in the allowed list. 
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
}
