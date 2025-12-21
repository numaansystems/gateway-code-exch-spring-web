# Legacy Application Gateway Authentication Integration

This directory contains complete implementation files for integrating legacy Java web applications with a centralized OAuth2 gateway for Single Sign-On (SSO).

## 📁 Contents

```
legacy/
├── src/
│   ├── main/
│   │   ├── java/com/example/legacyapp/filter/
│   │   │   └── GatewayAuthenticationFilter.java    # Main authentication filter
│   │   └── webapp/
│   │       ├── WEB-INF/
│   │       │   └── web.xml                         # Filter configuration
│   │       ├── home.jsp                             # Example authenticated page
│   │       ├── logout.jsp                           # Logout handler
│   │       └── error.html                           # Error page
│   └── test/
└── README.md                                        # This file
```

## 🎯 Purpose

These files enable legacy Java Servlet-based web applications to authenticate users through a centralized OAuth2 gateway, providing:

- **Single Sign-On (SSO)**: Users authenticate once at the gateway and access all integrated applications
- **OAuth2 Security**: Industry-standard OAuth2 authorization code flow with PKCE
- **Session Management**: Automatic token validation and session synchronization
- **Easy Integration**: Drop-in servlet filter with minimal configuration
- **Path Exclusions**: Configure public paths and static resources that don't require authentication

## 🏗️ Architecture

### Authentication Flow

```
┌─────────┐         ┌──────────┐         ┌─────────┐
│ Browser │         │  Legacy  │         │ Gateway │
│         │         │   App    │         │  (OAuth2)│
└────┬────┘         └────┬─────┘         └────┬────┘
     │                   │                     │
     │  1. Request Page  │                     │
     │──────────────────>│                     │
     │                   │                     │
     │  2. No Session    │                     │
     │                   │                     │
     │  3. Redirect to Gateway Auth           │
     │<──────────────────│                     │
     │                   │                     │
     │  4. Authorize (with PKCE)              │
     │────────────────────────────────────────>│
     │                   │                     │
     │  5. User Login    │                     │
     │<────────────────────────────────────────│
     │                   │                     │
     │  6. Authorization Code                  │
     │<────────────────────────────────────────│
     │                   │                     │
     │  7. Callback with Code                 │
     │──────────────────>│                     │
     │                   │                     │
     │                   │  8. Exchange Code   │
     │                   │────────────────────>│
     │                   │                     │
     │                   │  9. Access Token    │
     │                   │<────────────────────│
     │                   │                     │
     │                   │ 10. Get User Info   │
     │                   │────────────────────>│
     │                   │                     │
     │                   │ 11. User Details    │
     │                   │<────────────────────│
     │                   │                     │
     │ 12. Session Created                    │
     │                   │                     │
     │ 13. Redirect to Page                   │
     │<──────────────────│                     │
     │                   │                     │
     │ 14. Page Content  │                     │
     │<──────────────────│                     │
```

## 🚀 Integration Guide

### Prerequisites

- Java 8 or higher
- Servlet 3.1+ compatible container (Tomcat 8+, Jetty 9+, etc.)
- Access to OAuth2 gateway
- JSON library (org.json)

### Step 1: Add Dependencies

Add to your `pom.xml` (Maven) or `build.gradle` (Gradle):

**Maven:**
```xml
<dependency>
    <groupId>org.json</groupId>
    <artifactId>json</artifactId>
    <version>20230227</version>
</dependency>

<dependency>
    <groupId>javax.servlet</groupId>
    <artifactId>javax.servlet-api</artifactId>
    <version>4.0.1</version>
    <scope>provided</scope>
</dependency>
```

**Gradle:**
```gradle
implementation 'org.json:json:20230227'
compileOnly 'javax.servlet:javax.servlet-api:4.0.1'
```

### Step 2: Copy Filter Class

Copy `GatewayAuthenticationFilter.java` to your project:
```
src/main/java/com/example/legacyapp/filter/GatewayAuthenticationFilter.java
```

Adjust the package name if needed.

### Step 3: Configure web.xml

Add the filter configuration to your `WEB-INF/web.xml`:

```xml
<filter>
    <filter-name>GatewayAuthenticationFilter</filter-name>
    <filter-class>com.example.legacyapp.filter.GatewayAuthenticationFilter</filter-class>
    
    <init-param>
        <param-name>gatewayUrl</param-name>
        <param-value>http://localhost:8080</param-value>
    </init-param>
    
    <init-param>
        <param-name>excludedPaths</param-name>
        <param-value>/error.html,/logout.jsp,/public,/health</param-value>
    </init-param>
    
    <init-param>
        <param-name>excludedExtensions</param-name>
        <param-value>.css,.js,.png,.jpg,.jpeg,.gif,.ico</param-value>
    </init-param>
</filter>

<filter-mapping>
    <filter-name>GatewayAuthenticationFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

### Step 4: Add Supporting Pages

Copy the following files to your `src/main/webapp/` directory:
- `error.html` - Error handling page
- `logout.jsp` - Logout handler
- `home.jsp` - Example authenticated page (optional)

### Step 5: Configure for Your Environment

Update the `gatewayUrl` parameter in `web.xml` based on your environment:

**Development:**
```xml
<param-value>http://localhost:8080</param-value>
```

**QA:**
```xml
<param-value>https://gateway-qa.example.com</param-value>
```

**Production:**
```xml
<param-value>https://gateway.example.com</param-value>
```

## ⚙️ Configuration Options

### Filter Parameters

| Parameter | Required | Description | Example |
|-----------|----------|-------------|----------|
| `gatewayUrl` | Yes | Base URL of OAuth2 gateway | `http://localhost:8080` |
| `excludedPaths` | No | Comma-separated paths to exclude | `/error.html,/public,/health` |
| `excludedExtensions` | No | Comma-separated file extensions to exclude | `.css,.js,.png,.jpg` |

### Environment-Specific Configuration

For different environments, use Maven profiles or environment variables:

**Using Maven Profiles:**
```xml
<profiles>
    <profile>
        <id>dev</id>
        <properties>
            <gateway.url>http://localhost:8080</gateway.url>
        </properties>
    </profile>
    <profile>
        <id>prod</id>
        <properties>
            <gateway.url>https://gateway.example.com</gateway.url>
        </properties>
    </profile>
</profiles>
```

Then reference in `web.xml`:
```xml
<param-value>${gateway.url}</param-value>
```

## 🔒 Security Features

### OAuth2 with PKCE
The filter implements OAuth2 authorization code flow with Proof Key for Code Exchange (PKCE) to prevent authorization code interception attacks.

### State Parameter
CSRF protection using random state parameter validation.

### Session Security
- HttpOnly cookies (configure in web.xml)
- Secure cookies for HTTPS (enable in production)
- Session timeout configuration
- Automatic token validation

### Loop Detection
Prevents infinite redirect loops by tracking authentication attempts.

## 📊 Accessing User Information

Once authenticated, user information is stored in the session and can be accessed in your JSP/Servlet code:

**In JSP:**
```jsp
<%@ page import="org.json.JSONObject" %>
<%
    String userInfoStr = (String) session.getAttribute("userInfo");
    if (userInfoStr != null) {
        JSONObject userInfo = new JSONObject(userInfoStr);
        String username = userInfo.optString("username");
        String email = userInfo.optString("email");
        String name = userInfo.optString("name");
    }
%>
```

**In Servlet:**
```java
String userInfoStr = (String) request.getSession().getAttribute("userInfo");
if (userInfoStr != null) {
    JSONObject userInfo = new JSONObject(userInfoStr);
    String username = userInfo.optString("username");
    // Use user information
}
```

## 🧪 Testing

### Local Testing

1. **Start the Gateway:**
   ```bash
   cd gateway
   mvn spring-boot:run
   ```

2. **Deploy Legacy App:**
   ```bash
   mvn clean package
   # Deploy WAR to Tomcat or run embedded container
   ```

3. **Access Application:**
   - Navigate to `http://localhost:8081/your-app`
   - You should be redirected to gateway login
   - Login with test credentials
   - You should be redirected back to your app

### Test User Accounts

Create test users in the gateway:
```sql
INSERT INTO users (username, password, email, name, enabled) 
VALUES 
  ('testuser', '$2a$10$...', 'test@example.com', 'Test User', true),
  ('admin', '$2a$10$...', 'admin@example.com', 'Admin User', true);
```

### Testing Scenarios

1. **Happy Path:**
   - Access protected page → Redirect to gateway → Login → Redirect back → Access granted

2. **Session Expiry:**
   - Login → Wait for session timeout → Access page → Re-authenticate

3. **Token Validation:**
   - Login → Manually invalidate token at gateway → Access page → Re-authenticate

4. **Logout:**
   - Login → Access logout.jsp → Session cleared → Redirected to gateway logout

5. **Excluded Paths:**
   - Access `/error.html` → No authentication required
   - Access static resources → No authentication required

## 🔧 Troubleshooting

### Common Issues

**1. Infinite Redirect Loop**
- **Cause:** Gateway URL misconfigured or network issue
- **Solution:** Verify `gatewayUrl` is correct and accessible
- **Check:** Filter logs for "auth_loop" error

**2. Token Exchange Failed**
- **Cause:** Code verifier mismatch or expired code
- **Solution:** Clear browser cookies and try again
- **Check:** Gateway logs for token exchange errors

**3. No Username in Session**
- **Cause:** Gateway not returning user info
- **Solution:** Verify gateway `/api/userinfo` endpoint
- **Check:** Filter logs for "no_username" error

**4. Static Resources Not Loading**
- **Cause:** Extensions not in `excludedExtensions`
- **Solution:** Add missing extensions to configuration
- **Check:** Browser network tab for 302 redirects

### Debug Mode

Enable detailed logging in your servlet container:

**Tomcat (logging.properties):**
```properties
com.example.legacyapp.filter.level = FINE
```

**Check Filter Output:**
```bash
tail -f catalina.out | grep GatewayAuthenticationFilter
```

## 📝 Advanced Configuration

### Custom Error Handling

Modify `error.html` to match your application's look and feel, or redirect to a custom error page.

### Multiple Applications

Each legacy application can have its own client ID and configuration. Update the filter to use different client IDs:

```java
private String clientId;

@Override
public void init(FilterConfig filterConfig) {
    clientId = filterConfig.getInitParameter("clientId");
    if (clientId == null) {
        clientId = "legacy-app"; // default
    }
    // ... rest of initialization
}
```

### Session Persistence

For clustered environments, configure session replication in your container.

**Tomcat (context.xml):**
```xml
<Manager className="org.apache.catalina.session.PersistentManager">
    <Store className="org.apache.catalina.session.FileStore"
           directory="/path/to/sessions"/>
</Manager>
```

### Token Refresh

To implement token refresh, modify the filter to:
1. Store refresh token in session
2. Check token expiry before validation
3. Request new token using refresh token
4. Update session with new tokens

## 📚 Additional Resources

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [Servlet 4.0 Specification](https://javaee.github.io/servlet-spec/)

## 🤝 Support

For issues or questions:
1. Check the troubleshooting section
2. Review gateway logs
3. Enable debug logging
4. Contact your system administrator

## 📄 License

This integration code is provided as-is for use with the Gateway authentication system.

---

**Last Updated:** 2025-12-21  
**Version:** 1.0  
**Maintained By:** Gateway Integration Team