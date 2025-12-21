<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
    // Get the gateway URL from filter config or use default
    String gatewayUrl = application.getInitParameter("gatewayUrl");
    if (gatewayUrl == null || gatewayUrl.trim().isEmpty()) {
        gatewayUrl = "http://localhost:8080"; // Fallback default
    }
    
    // Remove trailing slash
    if (gatewayUrl.endsWith("/")) {
        gatewayUrl = gatewayUrl.substring(0, gatewayUrl.length() - 1);
    }
    
    // Invalidate the local session
    if (session != null) {
        session.invalidate();
    }
    
    // Redirect to gateway logout endpoint
    // The gateway will handle logout and redirect back to login page
    String gatewayLogoutUrl = gatewayUrl + "/logout";
    response.sendRedirect(gatewayLogoutUrl);
%>