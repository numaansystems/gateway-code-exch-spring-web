package com.example.legacyapp.filter;

import com.example.legacyapp.service.UserAuthorityService;
import com.example.legacyapp.service.UserAuthorityServiceImpl;
import org.json.JSONObject;
import org.json.JSONTokener;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Azure AD OAuth2 Callback Filter - Java 6 Compatible
 * 
 * Handles the OAuth2 authorization callback from Azure AD. This filter:
 * - Processes the authorization code received from Azure AD
 * - Exchanges the code for access and ID tokens
 * - Fetches user information from Microsoft Graph
 * - Loads additional authorities from the database
 * - Merges authorities from Azure AD and database
 * - Stores authentication state in HttpSession
 * 
 * This filter should be mapped to the OAuth2 callback path: /login/oauth2/code/azure
 * 
 * Configuration required in web.xml or Spring configuration:
 * - azureAd.clientId
 * - azureAd.clientSecret
 * - azureAd.tenantId
 * - azureAd.redirectUri
 * - azureAd.scope (optional, defaults to "openid profile email")
 * 
 * @author Legacy App Integration
 * @version 1.0
 */
public class AzureADCallbackFilter implements Filter {
    
    // Configuration parameters
    private String clientId;
    private String clientSecret;
    private String tenantId;
    private String redirectUri;
    private String scope = "openid profile email";
    
    // Azure AD endpoints
    private String tokenEndpoint;
    private String userInfoEndpoint;
    
    // User authority service for database lookups
    private UserAuthorityService userAuthorityService;
    
    // Session attribute keys - standardized with oauth2_ prefix
    private static final String SESSION_STATE_KEY = "oauth2_state";
    private static final String SESSION_ACCESS_TOKEN_KEY = "oauth2_access_token";
    private static final String SESSION_ID_TOKEN_KEY = "oauth2_id_token";
    private static final String SESSION_REFRESH_TOKEN_KEY = "oauth2_refresh_token";
    private static final String SESSION_USER_INFO_KEY = "oauth2_user_info";
    private static final String SESSION_AUTHORITIES_KEY = "oauth2_authorities";
    private static final String SESSION_TOKEN_EXPIRY_KEY = "oauth2_token_expiry";
    
    // Request parameter keys
    private static final String PARAM_CODE = "code";
    private static final String PARAM_STATE = "state";
    private static final String PARAM_ERROR = "error";
    private static final String PARAM_ERROR_DESCRIPTION = "error_description";
    
    /**
     * Initialize filter with configuration parameters
     */
    public void init(FilterConfig filterConfig) throws ServletException {
        // Read configuration from filter init parameters
        clientId = getConfigParameter(filterConfig, "azureAd.clientId");
        clientSecret = getConfigParameter(filterConfig, "azureAd.clientSecret");
        tenantId = getConfigParameter(filterConfig, "azureAd.tenantId");
        redirectUri = getConfigParameter(filterConfig, "azureAd.redirectUri");
        
        String scopeParam = filterConfig.getInitParameter("azureAd.scope");
        if (scopeParam != null && scopeParam.length() > 0) {
            scope = scopeParam;
        }
        
        // Validate required configuration
        if (clientId == null || clientSecret == null || tenantId == null || redirectUri == null) {
            throw new ServletException("Missing required Azure AD configuration parameters. " +
                "Required: azureAd.clientId, azureAd.clientSecret, azureAd.tenantId, azureAd.redirectUri");
        }
        
        // Construct Azure AD endpoints
        tokenEndpoint = String.format(
            "https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantId);
        userInfoEndpoint = "https://graph.microsoft.com/v1.0/me";
        
        // Initialize user authority service (optional - fails gracefully if DB not configured)
        userAuthorityService = new UserAuthorityServiceImpl();
        
        System.out.println("AzureADCallbackFilter initialized for tenant: " + tenantId);
    }
    
    /**
     * Main filter logic - handles OAuth2 callback
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        HttpSession session = httpRequest.getSession(true);
        
        // Check if this is an OAuth2 callback with authorization code
        String code = httpRequest.getParameter(PARAM_CODE);
        String state = httpRequest.getParameter(PARAM_STATE);
        String error = httpRequest.getParameter(PARAM_ERROR);
        
        // Handle OAuth2 error response
        if (error != null) {
            String errorDescription = httpRequest.getParameter(PARAM_ERROR_DESCRIPTION);
            handleAuthorizationError(httpResponse, error, errorDescription);
            return;
        }
        
        // Handle OAuth2 callback with authorization code
        if (code != null && state != null) {
            handleAuthorizationCallback(httpRequest, httpResponse, session, code, state);
            return;
        }
        
        // If no callback parameters, continue filter chain
        chain.doFilter(request, response);
    }
    
    /**
     * Clean up resources
     */
    public void destroy() {
        System.out.println("AzureADCallbackFilter destroyed");
    }
    
    /**
     * Handle OAuth2 callback with authorization code
     */
    private void handleAuthorizationCallback(HttpServletRequest request,
                                            HttpServletResponse response,
                                            HttpSession session,
                                            String code,
                                            String state) throws IOException, ServletException {
        System.out.println("AzureADCallbackFilter: Processing OAuth2 callback");
        
        // Validate state parameter (CSRF protection)
        String sessionState = (String) session.getAttribute(SESSION_STATE_KEY);
        if (sessionState == null || !sessionState.equals(state)) {
            throw new ServletException("Invalid state parameter - possible CSRF attack");
        }
        
        // Remove state from session
        session.removeAttribute(SESSION_STATE_KEY);
        
        try {
            // Exchange authorization code for access token
            Map<String, String> tokens = exchangeCodeForToken(code);
            
            String accessToken = tokens.get("access_token");
            String idToken = tokens.get("id_token");
            String refreshToken = tokens.get("refresh_token");
            String expiresIn = tokens.get("expires_in");
            
            // Store tokens in session with standardized keys
            session.setAttribute(SESSION_ACCESS_TOKEN_KEY, accessToken);
            if (idToken != null && idToken.length() > 0) {
                session.setAttribute(SESSION_ID_TOKEN_KEY, idToken);
            }
            if (refreshToken != null && refreshToken.length() > 0) {
                session.setAttribute(SESSION_REFRESH_TOKEN_KEY, refreshToken);
            }
            
            // Calculate and store token expiry time
            if (expiresIn != null && expiresIn.length() > 0) {
                long expiryTime = System.currentTimeMillis() + 
                    (Long.parseLong(expiresIn) * 1000);
                session.setAttribute(SESSION_TOKEN_EXPIRY_KEY, new Long(expiryTime));
            }
            
            // Fetch and store user info
            Map<String, Object> userInfo = fetchUserInfo(accessToken);
            session.setAttribute(SESSION_USER_INFO_KEY, userInfo);
            
            // Extract username for authority lookup
            String username = extractUsername(userInfo);
            System.out.println("AzureADCallbackFilter: Authenticated user: " + username);
            
            // Check if user exists in database
            if (userAuthorityService != null) {
                try {
                    Collection<String> dbAuthorities = 
                        userAuthorityService.loadAuthoritiesByUsername(username);
                    
                    // If no authorities found, user doesn't exist in database
                    if (dbAuthorities == null || dbAuthorities.size() == 0) {
                        System.err.println("AzureADCallbackFilter: User not found in database: " + username);
                        redirectToUnauthorized(request, response);
                        return;
                    }
                } catch (Exception e) {
                    System.err.println("AzureADCallbackFilter: Error checking user in database: " + 
                                     e.getMessage());
                    e.printStackTrace();
                    // If database check fails, redirect to unauthorized
                    redirectToUnauthorized(request, response);
                    return;
                }
            }
            
            // Load and merge authorities
            Collection<String> mergedAuthorities = loadAndMergeAuthorities(username, idToken);
            session.setAttribute(SESSION_AUTHORITIES_KEY, mergedAuthorities);
            
            System.out.println("AzureADCallbackFilter: Stored " + mergedAuthorities.size() + 
                             " authorities in session");
            
            // Store authentication state in session
            session.setAttribute("authenticated", Boolean.TRUE);
            session.setAttribute("userPrincipal", username);
            
            System.out.println("AzureADCallbackFilter: Authentication successful, redirecting to home");
            
            // Redirect to home page
            String contextPath = request.getContextPath();
            String redirectUrl = (contextPath != null && contextPath.length() > 0) 
                ? contextPath + "/" 
                : "/";
            response.sendRedirect(redirectUrl);
            
        } catch (Exception e) {
            System.err.println("AzureADCallbackFilter: Failed to complete OAuth2 flow: " + 
                             e.getMessage());
            e.printStackTrace();
            throw new ServletException("Failed to complete OAuth2 flow", e);
        }
    }
    
    /**
     * Exchange authorization code for access token
     */
    private Map<String, String> exchangeCodeForToken(String code) throws IOException {
        System.out.println("AzureADCallbackFilter: Exchanging authorization code for tokens");
        
        // Build token request body
        StringBuilder requestBody = new StringBuilder();
        requestBody.append("client_id=").append(urlEncode(clientId));
        requestBody.append("&client_secret=").append(urlEncode(clientSecret));
        requestBody.append("&code=").append(urlEncode(code));
        requestBody.append("&redirect_uri=").append(urlEncode(redirectUri));
        requestBody.append("&grant_type=authorization_code");
        requestBody.append("&scope=").append(urlEncode(scope));
        
        // Send token request
        String responseBody = sendPostRequest(tokenEndpoint, requestBody.toString());
        
        // Parse JSON response
        JSONObject jsonResponse = new JSONObject(new JSONTokener(responseBody));
        
        Map<String, String> tokens = new HashMap<String, String>();
        tokens.put("access_token", jsonResponse.optString("access_token"));
        tokens.put("id_token", jsonResponse.optString("id_token"));
        tokens.put("expires_in", jsonResponse.optString("expires_in"));
        tokens.put("refresh_token", jsonResponse.optString("refresh_token"));
        
        System.out.println("AzureADCallbackFilter: Successfully exchanged code for tokens");
        return tokens;
    }
    
    /**
     * Fetch user information from Microsoft Graph API
     */
    private Map<String, Object> fetchUserInfo(String accessToken) throws IOException {
        System.out.println("AzureADCallbackFilter: Fetching user info from Microsoft Graph");
        
        String responseBody = sendGetRequest(userInfoEndpoint, accessToken);
        
        JSONObject jsonResponse = new JSONObject(new JSONTokener(responseBody));
        
        Map<String, Object> userInfo = new HashMap<String, Object>();
        userInfo.put("id", jsonResponse.optString("id"));
        userInfo.put("displayName", jsonResponse.optString("displayName"));
        userInfo.put("givenName", jsonResponse.optString("givenName"));
        userInfo.put("surname", jsonResponse.optString("surname"));
        userInfo.put("userPrincipalName", jsonResponse.optString("userPrincipalName"));
        userInfo.put("mail", jsonResponse.optString("mail"));
        userInfo.put("jobTitle", jsonResponse.optString("jobTitle"));
        
        System.out.println("AzureADCallbackFilter: User info retrieved successfully");
        return userInfo;
    }
    
    /**
     * Extract username from user info (prefers mail, falls back to userPrincipalName)
     */
    private String extractUsername(Map<String, Object> userInfo) {
        String mail = (String) userInfo.get("mail");
        if (mail != null && mail.length() > 0) {
            return mail;
        }
        String userPrincipalName = (String) userInfo.get("userPrincipalName");
        if (userPrincipalName != null && userPrincipalName.length() > 0) {
            return userPrincipalName;
        }
        return "unknown";
    }
    
    /**
     * Load authorities from Azure AD and database, then merge them
     */
    private Collection<String> loadAndMergeAuthorities(String username, String idToken) {
        System.out.println("AzureADCallbackFilter: Loading and merging authorities");
        
        Set<String> allAuthorities = new HashSet<String>();
        
        // Extract authorities from Azure AD ID token (roles claim)
        Collection<String> azureAuthorities = extractAzureAuthorities(idToken);
        if (azureAuthorities != null && azureAuthorities.size() > 0) {
            System.out.println("AzureADCallbackFilter: Found " + azureAuthorities.size() + 
                             " Azure AD authorities");
            allAuthorities.addAll(azureAuthorities);
        }
        
        // Load authorities from database
        if (userAuthorityService != null) {
            try {
                Collection<String> dbAuthorities = 
                    userAuthorityService.loadAuthoritiesByUsername(username);
                if (dbAuthorities != null && dbAuthorities.size() > 0) {
                    System.out.println("AzureADCallbackFilter: Found " + dbAuthorities.size() + 
                                     " database authorities");
                    allAuthorities.addAll(dbAuthorities);
                }
            } catch (Exception e) {
                System.err.println("AzureADCallbackFilter: Failed to load database authorities: " + 
                                 e.getMessage());
                // Continue without database authorities
            }
        }
        
        System.out.println("AzureADCallbackFilter: Total merged authorities: " + 
                         allAuthorities.size());
        return new ArrayList<String>(allAuthorities);
    }
    
    /**
     * Extract authorities from Azure AD ID token
     * 
     * KNOWN LIMITATION: This is a simplified implementation that does not decode JWT tokens.
     * In a production environment, you should:
     * 1. Add a JWT library (e.g., java-jwt, nimbus-jose-jwt)
     * 2. Decode the ID token
     * 3. Validate the signature
     * 4. Extract the 'roles' claim
     * 
     * For now, this returns an empty collection, which means only database authorities
     * will be loaded. This is sufficient for applications that manage all authorities
     * in their database.
     * 
     * @param idToken the ID token from Azure AD
     * @return collection of authority strings from Azure AD (currently empty)
     */
    private Collection<String> extractAzureAuthorities(String idToken) {
        if (idToken == null || idToken.length() == 0) {
            return new ArrayList<String>();
        }
        
        // TODO: Implement JWT decoding and role extraction
        // This requires adding a JWT library dependency
        // Example with nimbus-jose-jwt:
        // try {
        //     SignedJWT signedJWT = SignedJWT.parse(idToken);
        //     JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        //     List<String> roles = (List<String>) claims.getClaim("roles");
        //     return roles != null ? roles : new ArrayList<String>();
        // } catch (Exception e) {
        //     System.err.println("Failed to parse ID token: " + e.getMessage());
        //     return new ArrayList<String>();
        // }
        
        return new ArrayList<String>();
    }
    
    /**
     * Handle authorization error from Azure AD
     */
    private void handleAuthorizationError(HttpServletResponse response, 
                                         String error, 
                                         String errorDescription) throws IOException {
        System.err.println("AzureADCallbackFilter: Authorization error: " + error);
        if (errorDescription != null) {
            System.err.println("AzureADCallbackFilter: Error description: " + errorDescription);
        }
        
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("text/html");
        
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h1>Authentication Error</h1>");
        html.append("<p><strong>Error:</strong> ").append(escapeHtml(error)).append("</p>");
        if (errorDescription != null) {
            html.append("<p><strong>Description:</strong> ")
                .append(escapeHtml(errorDescription)).append("</p>");
        }
        html.append("<p><a href=\"/\">Return to home</a></p>");
        html.append("</body></html>");
        
        response.getWriter().write(html.toString());
    }
    
    /**
     * Send HTTP POST request
     */
    private String sendPostRequest(String urlString, String requestBody) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        try {
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            connection.setDoOutput(true);
            
            // Write request body
            OutputStream os = connection.getOutputStream();
            try {
                os.write(requestBody.getBytes("UTF-8"));
                os.flush();
            } finally {
                os.close();
            }
            
            // Read response
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                return readResponse(connection);
            } else {
                throw new IOException("HTTP error code: " + responseCode);
            }
        } finally {
            connection.disconnect();
        }
    }
    
    /**
     * Send HTTP GET request with bearer token
     */
    private String sendGetRequest(String urlString, String accessToken) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        try {
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Authorization", "Bearer " + accessToken);
            connection.setRequestProperty("Accept", "application/json");
            
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                return readResponse(connection);
            } else {
                throw new IOException("HTTP error code: " + responseCode);
            }
        } finally {
            connection.disconnect();
        }
    }
    
    /**
     * Read HTTP response body
     */
    private String readResponse(HttpURLConnection connection) throws IOException {
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream(), "UTF-8"));
        try {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            return response.toString();
        } finally {
            reader.close();
        }
    }
    
    /**
     * Get configuration parameter from filter config or system properties
     */
    private String getConfigParameter(FilterConfig filterConfig, String paramName) {
        String value = filterConfig.getInitParameter(paramName);
        if (value == null || value.trim().length() == 0) {
            // Try system property as fallback
            value = System.getProperty(paramName);
        }
        return value;
    }
    
    /**
     * URL encode string (Java 6 compatible)
     */
    private String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported", e);
        }
    }
    
    /**
     * Escape HTML special characters
     */
    private String escapeHtml(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }
    
    /**
     * Redirect to unauthorized error page
     */
    private void redirectToUnauthorized(HttpServletRequest request, 
                                       HttpServletResponse response) throws IOException {
        String contextPath = request.getContextPath();
        String unauthorizedUrl = (contextPath != null && contextPath.length() > 0) 
            ? contextPath + "/unauthorized" 
            : "/unauthorized";
        response.sendRedirect(unauthorizedUrl);
    }
}
