package com.example.legacyapp.servlet;

import javax.servlet.ServletException;
import javax.servlet. http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io. OutputStream;
import java.net. HttpURLConnection;
import java. net.URL;
import java. net.URLEncoder;

/**
 * Handles OAuth callback from gateway with token validation
 */
public class CallbackServlet extends HttpServlet {
    
    private String gatewayUrl;
    
    @Override
    public void init() throws ServletException {
        gatewayUrl = getServletContext().getInitParameter("gatewayUrl");
        if (gatewayUrl == null) {
            gatewayUrl = "https://gateway-domain/gateway";
        }
    }
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        
        System.out.println("==========================================");
        System.out.println("CALLBACK SERVLET - Processing callback");
        
        // Get token from query parameter
        String token = request.getParameter("token");
        String returnUrl = request.getParameter("returnUrl");
        
        if (token == null || token.length() == 0) {
            System.err.println("CALLBACK - No token parameter!");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing token");
            return;
        }
        
        System.out.println("CALLBACK - Token:  " + token. substring(0, Math.min(10, token.length())) + "...");
        System.out.println("CALLBACK - ReturnUrl: " + returnUrl);
        
        // Validate token with gateway
        TokenValidationResponse validation = validateToken(token);
        
        if (validation == null || ! validation.success) {
            System.err. println("CALLBACK - Token validation FAILED");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
            return;
        }
        
        System.out.println("CALLBACK - Token validation SUCCESS");
        System.out.println("CALLBACK - Username: " + validation.username);
        
        // Create session
        HttpSession session = request.getSession(true);
        session.setAttribute("authenticated", true);
        session.setAttribute("username", validation.username);
        session.setAttribute("email", validation.email);
        session.setAttribute("name", validation.name);
        session.setAttribute("authorities", validation.authorities);
        
        System.out.println("CALLBACK - Session created:  " + session.getId());
        
        // Redirect to return URL or home
        String redirectUrl = (returnUrl != null && returnUrl.length() > 0) 
            ? returnUrl 
            : request.getContextPath() + "/";
        
        System.out. println("CALLBACK - Redirecting to: " + redirectUrl);
        System.out.println("==========================================");
        
        response. sendRedirect(redirectUrl);
    }
    
    private TokenValidationResponse validateToken(String token) {
        HttpURLConnection conn = null;
        OutputStream os = null;
        BufferedReader in = null;
        
        try {
            URL url = new URL(gatewayUrl + "/auth/validate-token");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            
            String postData = "token=" + URLEncoder.encode(token, "UTF-8");
            os = conn.getOutputStream();
            os.write(postData.getBytes("UTF-8"));
            os.flush();
            
            int responseCode = conn.getResponseCode();
            System.out. println("CALLBACK - Gateway response: " + responseCode);
            
            if (responseCode == HttpURLConnection.HTTP_OK) {
                in = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
                StringBuffer responseBuffer = new StringBuffer();
                String line;
                while ((line = in.readLine()) != null) {
                    responseBuffer.append(line);
                }
                
                return parseResponse(responseBuffer.toString());
            }
            
        } catch (Exception e) {
            System. err.println("CALLBACK - Error validating token: " + e. getMessage());
            e.printStackTrace();
        } finally {
            if (os != null) try { os.close(); } catch (IOException e) {}
            if (in != null) try { in.close(); } catch (IOException e) {}
            if (conn != null) conn.disconnect();
        }
        
        return null;
    }
    
    private TokenValidationResponse parseResponse(String json) {
        TokenValidationResponse response = new TokenValidationResponse();
        response.success = json.indexOf("\"success\": true") >= 0;
        
        if (response.success) {
            response. username = extractValue(json, "username");
            response.email = extractValue(json, "email");
            response.name = extractValue(json, "name");
            response.authorities = extractValue(json, "authorities");
        }
        
        return response;
    }
    
    private String extractValue(String json, String key) {
        String searchKey = "\"" + key + "\": \"";
        int start = json. indexOf(searchKey);
        if (start < 0) return "";
        start += searchKey.length();
        int end = json.indexOf("\"", start);
        return (end < 0) ? "" : json.substring(start, end);
    }
    
    private static class TokenValidationResponse {
        boolean success;
        String username;
        String email;
        String name;
        String authorities;
    }
}
