<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="org.json.JSONObject" %>
<%
    // Get user info from session
    String userInfoStr = (String) session.getAttribute("userInfo");
    if (userInfoStr == null) {
        response.sendRedirect("error.html?error=no_session");
        return;
    }
    
    JSONObject userInfo = new JSONObject(userInfoStr);
    String username = userInfo.optString("username", "Unknown");
    String email = userInfo.optString("email", "Not provided");
    String name = userInfo.optString("name", "Not provided");
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome - Legacy Application</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            border-radius: 12px;
            padding: 20px 30px;
            margin-bottom: 20px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 18px;
        }
        
        .user-name {
            font-weight: 500;
            color: #2c3e50;
        }
        
        .logout-btn {
            padding: 8px 20px;
            background: #ff4757;
            color: white;
            border: none;
            border-radius: 6px;
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .logout-btn:hover {
            background: #ee5a6f;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(255, 71, 87, 0.4);
        }
        
        .content {
            background: white;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }
        
        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 32px;
        }
        
        .subtitle {
            color: #7f8c8d;
            margin-bottom: 30px;
            font-size: 16px;
        }
        
        .info-card {
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }
        
        .info-card h2 {
            color: #2c3e50;
            font-size: 18px;
            margin-bottom: 15px;
        }
        
        .info-row {
            display: flex;
            padding: 10px 0;
            border-bottom: 1px solid #ecf0f1;
        }
        
        .info-row:last-child {
            border-bottom: none;
        }
        
        .info-label {
            font-weight: 600;
            color: #34495e;
            min-width: 120px;
        }
        
        .info-value {
            color: #7f8c8d;
        }
        
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }
        
        .feature-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 8px;
            transition: transform 0.3s ease;
        }
        
        .feature-card:hover {
            transform: translateY(-5px);
        }
        
        .feature-card h3 {
            font-size: 18px;
            margin-bottom: 10px;
        }
        
        .feature-card p {
            font-size: 14px;
            opacity: 0.9;
            line-height: 1.5;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            background: #2ecc71;
            color: white;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            margin-left: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🏢 Legacy Application</div>
            <div class="user-info">
                <div class="user-avatar"><%= username.substring(0, 1).toUpperCase() %></div>
                <div class="user-name"><%= username %></div>
                <a href="logout.jsp" class="logout-btn">Logout</a>
            </div>
        </div>
        
        <div class="content">
            <h1>Welcome, <%= name %>! <span class="badge">Authenticated</span></h1>
            <p class="subtitle">You are successfully logged in to the legacy application via Gateway SSO</p>
            
            <div class="info-card">
                <h2>📋 Your Session Information</h2>
                <div class="info-row">
                    <div class="info-label">Username:</div>
                    <div class="info-value"><%= username %></div>
                </div>
                <div class="info-row">
                    <div class="info-label">Email:</div>
                    <div class="info-value"><%= email %></div>
                </div>
                <div class="info-row">
                    <div class="info-label">Display Name:</div>
                    <div class="info-value"><%= name %></div>
                </div>
                <div class="info-row">
                    <div class="info-label">Session ID:</div>
                    <div class="info-value"><%= session.getId() %></div>
                </div>
                <div class="info-row">
                    <div class="info-label">Session Created:</div>
                    <div class="info-value"><%= new java.util.Date(session.getCreationTime()) %></div>
                </div>
            </div>
            
            <div class="features">
                <div class="feature-card">
                    <h3>🔐 Single Sign-On</h3>
                    <p>Authenticate once and access all integrated applications seamlessly.</p>
                </div>
                <div class="feature-card">
                    <h3>🛡️ OAuth2 Security</h3>
                    <p>Protected by industry-standard OAuth2 with PKCE authorization flow.</p>
                </div>
                <div class="feature-card">
                    <h3>⚡ Session Management</h3>
                    <p>Automatic token validation and session synchronization across apps.</p>
                </div>
                <div class="feature-card">
                    <h3>🔄 Seamless Integration</h3>
                    <p>Easy integration with existing legacy applications using servlet filters.</p>
                </div>
            </div>
            
            <div class="info-card" style="margin-top: 30px;">
                <h2>ℹ️ About This Application</h2>
                <p style="color: #7f8c8d; line-height: 1.6; margin-top: 10px;">
                    This is a demonstration of a legacy Java web application integrated with a centralized 
                    OAuth2 gateway. The application uses a servlet filter to intercept all requests and 
                    enforce authentication through the gateway. Once authenticated, user information is 
                    stored in the session and can be accessed throughout the application.
                </p>
            </div>
        </div>
    </div>
</body>
</html>