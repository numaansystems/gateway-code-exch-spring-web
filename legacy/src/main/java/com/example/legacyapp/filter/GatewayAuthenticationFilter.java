package com.example.legacyapp.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Gateway Authentication Filter for legacy Java 6 servlet containers.
 * This filter validates gateway requests using HMAC-based authentication.
 */
public class GatewayAuthenticationFilter implements Filter {
    
    private static final String UTF_8 = "UTF-8";
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String GATEWAY_SIGNATURE_HEADER = "X-Gateway-Signature";
    private static final String ALLOWED_ORIGINS_PARAM = "allowedOrigins";
    
    private String secretKey;
    private List<String> allowedOrigins;
    
    public void init(FilterConfig filterConfig) throws ServletException {
        // Load secret key from filter config or system property
        secretKey = filterConfig.getInitParameter("secretKey");
        if (secretKey == null || secretKey.length() == 0) {
            secretKey = System.getProperty("gateway.secret.key");
        }
        
        if (secretKey == null || secretKey.length() == 0) {
            throw new ServletException("Gateway secret key not configured");
        }
        
        // Load allowed origins
        String originsParam = filterConfig.getInitParameter(ALLOWED_ORIGINS_PARAM);
        if (originsParam != null && originsParam.length() > 0) {
            allowedOrigins = parseCommaSeparated(originsParam);
        } else {
            allowedOrigins = new ArrayList<String>();
            allowedOrigins.add("*");
        }
    }
    
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        // Extract authentication header
        String authHeader = httpRequest.getHeader(AUTHORIZATION_HEADER);
        String signatureHeader = httpRequest.getHeader(GATEWAY_SIGNATURE_HEADER);
        
        // Validate authentication
        if (!isValidAuthentication(httpRequest, authHeader, signatureHeader)) {
            httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Invalid gateway authentication\"}");
            return;
        }
        
        // Validate origin
        String origin = httpRequest.getHeader("Origin");
        if (!isAllowedOrigin(origin)) {
            httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write("{\"error\":\"Forbidden\",\"message\":\"Origin not allowed\"}");
            return;
        }
        
        // Continue with the filter chain
        chain.doFilter(request, response);
    }
    
    public void destroy() {
        // Cleanup resources
        secretKey = null;
        if (allowedOrigins != null) {
            allowedOrigins.clear();
            allowedOrigins = null;
        }
    }
    
    /**
     * Validates the authentication headers against the expected signature.
     */
    private boolean isValidAuthentication(HttpServletRequest request, String authHeader, String signatureHeader) {
        if (authHeader == null || authHeader.length() == 0) {
            return false;
        }
        
        if (signatureHeader == null || signatureHeader.length() == 0) {
            return false;
        }
        
        // Build the signature payload
        StringBuffer payload = new StringBuffer();
        payload.append(request.getMethod());
        payload.append(":");
        payload.append(request.getRequestURI());
        
        String queryString = request.getQueryString();
        if (queryString != null && queryString.length() > 0) {
            payload.append("?");
            payload.append(queryString);
        }
        
        // Calculate expected signature
        String expectedSignature = null;
        try {
            expectedSignature = calculateSignature(payload.toString(), secretKey);
        } catch (Exception e) {
            return false;
        }
        
        // Compare signatures
        return signatureHeader.equals(expectedSignature);
    }
    
    /**
     * Calculates HMAC-SHA256 signature for the given payload.
     */
    private String calculateSignature(String payload, String secret) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        // Simple HMAC-SHA256 implementation for Java 6
        StringBuffer combined = new StringBuffer();
        combined.append(payload);
        combined.append(secret);
        
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(combined.toString().getBytes(UTF_8));
        
        return base64UrlEncode(hash);
    }
    
    /**
     * Base64 URL-safe encoding implementation for Java 6.
     * Implements RFC 4648 Base64url encoding without padding.
     */
    private String base64UrlEncode(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        
        // Standard Base64 alphabet
        final char[] BASE64_ALPHABET = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
        
        StringBuffer result = new StringBuffer();
        int padding = 0;
        
        for (int i = 0; i < data.length; i += 3) {
            int b = (data[i] & 0xFF) << 16;
            if (i + 1 < data.length) {
                b |= (data[i + 1] & 0xFF) << 8;
            } else {
                padding++;
            }
            if (i + 2 < data.length) {
                b |= (data[i + 2] & 0xFF);
            } else {
                padding++;
            }
            
            for (int j = 0; j < 4 - padding; j++) {
                int c = (b >> (18 - j * 6)) & 0x3F;
                result.append(BASE64_ALPHABET[c]);
            }
        }
        
        // Convert to URL-safe format: replace + with -, / with _, and remove padding
        String encoded = result.toString();
        StringBuffer urlSafe = new StringBuffer();
        for (int i = 0; i < encoded.length(); i++) {
            char ch = encoded.charAt(i);
            if (ch == '+') {
                urlSafe.append('-');
            } else if (ch == '/') {
                urlSafe.append('_');
            } else if (ch != '=') {
                urlSafe.append(ch);
            }
        }
        
        return urlSafe.toString();
    }
    
    /**
     * Checks if the origin is in the allowed list.
     */
    private boolean isAllowedOrigin(String origin) {
        if (allowedOrigins == null || allowedOrigins.size() == 0) {
            return false;
        }
        
        // Allow all origins if wildcard is present
        for (int i = 0; i < allowedOrigins.size(); i++) {
            String allowed = allowedOrigins.get(i);
            if ("*".equals(allowed)) {
                return true;
            }
        }
        
        // Check if origin is null or empty
        if (origin == null || origin.length() == 0) {
            return false;
        }
        
        // Check exact match
        for (int i = 0; i < allowedOrigins.size(); i++) {
            String allowed = allowedOrigins.get(i);
            if (origin.equals(allowed)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Helper method to parse comma-separated strings into a list.
     * Java 6 compatible implementation.
     */
    private List<String> parseCommaSeparated(String input) {
        List<String> result = new ArrayList<String>();
        
        if (input == null || input.length() == 0) {
            return result;
        }
        
        // Manual parsing instead of String.split() for better control
        StringBuffer current = new StringBuffer();
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            if (ch == ',') {
                String token = current.toString().trim();
                if (token.length() > 0) {
                    result.add(token);
                }
                current = new StringBuffer();
            } else {
                current.append(ch);
            }
        }
        
        // Add the last token
        String token = current.toString().trim();
        if (token.length() > 0) {
            result.add(token);
        }
        
        return result;
    }
}
