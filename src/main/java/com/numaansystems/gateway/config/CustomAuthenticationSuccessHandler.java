package com.numaansystems.gateway.config;

import com.numaansystems.gateway.service.ExchangeTokenService;
import com.numaansystems.gateway. service.UserAuthorityService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j. Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core. GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org. springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

/**
 * Custom authentication success handler for Azure AD OAuth2 login.
 */
@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

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
    
    HttpSession session = request.getSession(false);
    String returnUrl = (String) (session != null ? session.getAttribute("returnUrl") : null);
    String finalReturnUrl = (String) (session != null ? session.getAttribute("finalReturnUrl") : null);

    logger.info("Authentication success handler invoked");
    logger.info("Return URL (callback): {}", returnUrl);
    logger.info("Final return URL (destination): {}", finalReturnUrl);

    if (returnUrl != null && !returnUrl.isEmpty()) {
        if (! isAllowedDomain(returnUrl)) {
            logger.warn("Unauthorized redirect domain attempted: {}", returnUrl);
            response.sendRedirect("/");
            return;
        }

        // Extract user information
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oauth2User = oauthToken.getPrincipal();
        Map<String, Object> attributes = oauth2User.getAttributes();

        String username = (String) attributes.getOrDefault("preferred_username", attributes.get("email"));
        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");

        logger.info("Processing authentication success for user: {}", username);

        // Merge authorities
        Set<String> authorities = new HashSet<>();

        Object rolesObj = attributes.get("roles");
        if (rolesObj instanceof List) {
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) rolesObj;
            authorities.addAll(roles);
        }

        for (GrantedAuthority authority : oauth2User.getAuthorities()) {
            authorities.add(authority. getAuthority());
        }

        if (userAuthorityService != null) {
            try {
                Collection<String> dbAuthorities = userAuthorityService.loadAuthoritiesByUsername(username);
                authorities.addAll(dbAuthorities);
            } catch (Exception e) {
                logger.warn("Failed to load database authorities: {}", e.getMessage());
            }
        }

        // Create exchange token
        String token = exchangeTokenService.createToken(username, email, name, authorities);
        logger.info("Created exchange token for user {}", username);

        // Build callback URL with token AND finalReturnUrl
        String separator = returnUrl.contains("?") ? "&" : "?";
        String callbackUrl = returnUrl + separator + "token=" + token;
        
        // Add finalReturnUrl if present
        if (finalReturnUrl != null && !finalReturnUrl.isEmpty()) {
            callbackUrl += "&returnUrl=" + java.net.URLEncoder.encode(finalReturnUrl, "UTF-8");
        }

        // Clean up session
        if (session != null) {
            session.removeAttribute("returnUrl");
            session.removeAttribute("finalReturnUrl");
        }

        logger.info("Redirecting to: {}", callbackUrl);
        response.sendRedirect(callbackUrl);
    } else {
        logger.warn("No returnUrl found in session");
        response.sendRedirect("/");
    }
}

    /**
     * Build callback URL from returnUrl by extracting protocol, host, port, and context path. 
     * Then append /auth/callback with token parameter.
     * 
     * Examples:
     *   Input:  http://localhost:8080/myapp/index. html
     *   Output: http://localhost:8080/myapp/auth/callback?token=xxx
     * 
     *   Input:  http://localhost:8080/index.html
     *   Output: http://localhost:8080/auth/callback?token=xxx
     */
    private String buildCallbackUrl(String returnUrl, String token) {
        try {
            URL url = new URL(returnUrl);
            
            // Extract components
            String protocol = url.getProtocol();
            String host = url.getHost();
            int port = url.getPort();
            String path = url.getPath();
            
            // Build base URL with port if needed
            StringBuilder baseUrl = new StringBuilder();
            baseUrl. append(protocol).append("://"). append(host);
            if (port != -1 && port != 80 && port != 443) {
                baseUrl.append(":").append(port);
            }
            
            // Extract context path from the path
            // E.g., /myapp/index.html -> /myapp
            //       /index.html -> ""
            String contextPath = "";
            if (path != null && !path.isEmpty()) {
                int secondSlash = path.indexOf('/', 1);
                if (secondSlash > 0) {
                    // Path has at least two segments: /myapp/index.html
                    contextPath = path.substring(0, secondSlash);
                } else if (path.length() > 1 && !path.contains(".")) {
                    // Path is just /myapp without trailing file
                    contextPath = path;
                }
            }
            
            // Build callback URL
            String callbackUrl = baseUrl.toString() + contextPath + "/auth/callback?token=" + token;
            
            logger.debug("Built callback URL:");
            logger.debug("  Return URL: {}", returnUrl);
            logger.debug("  Base URL: {}", baseUrl);
            logger.debug("  Context Path: {}", contextPath.isEmpty() ? "(root)" : contextPath);
            logger.debug("  Callback URL: {}", callbackUrl);
            
            return callbackUrl;
            
        } catch (MalformedURLException e) {
            logger.error("Failed to parse returnUrl: {}", returnUrl, e);
            // Fallback: just append token to returnUrl
            return returnUrl + (returnUrl.contains("? ") ? "&" : "?") + "token=" + token;
        }
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
