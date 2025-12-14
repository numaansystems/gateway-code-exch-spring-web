package com.numaansystems.gateway.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

/**
 * Test controller for verifying OAuth flow and authentication.
 * 
 * <p>Provides test endpoints to verify that the gateway authentication
 * and OAuth flow are working correctly.</p>
 * 
 * @author Numaan Systems
 * @version 0.1.0
 */
@Controller
@RequestMapping("/test")
public class TestController {

    /**
     * Public test endpoint that doesn't require authentication.
     * 
     * @return JSON response with endpoint information
     */
    @GetMapping("/public")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> publicEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("endpoint", "/test/public");
        response.put("access", "public");
        response.put("message", "This endpoint is accessible without authentication");
        response.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(response);
    }

    /**
     * Protected test endpoint that requires authentication.
     * 
     * @param authentication the current authentication object
     * @return JSON response with user information
     */
    @GetMapping("/protected")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> protectedEndpoint(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        response.put("endpoint", "/test/protected");
        response.put("access", "protected");
        response.put("message", "This endpoint requires authentication");
        response.put("timestamp", System.currentTimeMillis());
        
        if (authentication != null) {
            response.put("authenticated", true);
            response.put("username", authentication.getName());
            response.put("authorities", authentication.getAuthorities());
        } else {
            response.put("authenticated", false);
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * Test page for OAuth callback flow.
     * 
     * @return the view name for the callback test page
     */
    @GetMapping("/callback-test")
    public String callbackTest() {
        return "test-callback.html";
    }
}
