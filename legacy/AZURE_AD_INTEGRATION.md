# Azure AD Direct Integration - Redirect Loop Fix

## Overview

This document describes the changes made to fix the redirect loop issue in the Azure AD OAuth2 direct integration for legacy applications.

## Problem

The original implementation had a **redirect loop** between authentication checking and callback handling:

1. `AzureADOAuth2Filter` checked for session key `"oauth2_access_token"`
2. The callback handling code (within the same filter) stored session key `"access_token"` (wrong key!)
3. After successful Azure AD authentication, the callback redirected to `/`, but the OAuth2 filter didn't recognize the user as authenticated
4. The filter would redirect to Azure AD again, creating an infinite loop
5. Additionally, `AzureADOAuth2Filter` was intercepting the callback path `/login/oauth2/code/azure`, potentially causing issues

## Solution

### 1. Separation of Concerns

Split the authentication logic into two separate filters:

- **`AzureADOAuth2Filter`**: Checks if user is authenticated and initiates OAuth2 flow
- **`AzureADCallbackFilter`**: Handles the OAuth2 callback from Azure AD

### 2. Standardized Session Keys

Both filters now use consistent session attribute keys with `oauth2_` prefix:

- `oauth2_access_token` - Access token from Azure AD
- `oauth2_id_token` - ID token from Azure AD
- `oauth2_refresh_token` - Refresh token from Azure AD
- `oauth2_user_info` - User information from Microsoft Graph
- `oauth2_authorities` - Merged authorities (Azure AD + database)

### 3. Cookie-Based Authentication State

Added `LEGACY_AUTH` cookie to persist authentication state:

- **Name**: `LEGACY_AUTH`
- **Value**: `true` when authenticated
- **HttpOnly**: `true` (prevents JavaScript access)
- **Secure**: `true` (should be enabled in production)
- **Path**: `/` (available to all paths)
- **MaxAge**: 1800 seconds (30 minutes)

### 4. Database Authority Lookup

Created service layer to load user authorities from database:

- **`UserAuthorityService`**: Interface for loading authorities
- **`UserAuthorityServiceImpl`**: JDBC-based implementation (Java 6 compatible)

Authorities are merged from two sources:
1. Azure AD roles (from ID token claims)
2. Database authorities (from `authorities` and `user_authorities` tables)

## Files Changed

### Modified Files

1. **`legacy/src/main/java/com/example/legacyapp/filter/AzureADOAuth2Filter.java`**
   - Added `/login/oauth2/code/azure` to `EXCLUDED_PATHS`
   - Updated `isAuthenticated()` to check both session token and `LEGACY_AUTH` cookie
   - Removed callback handling logic (moved to `AzureADCallbackFilter`)
   - Removed unused methods: `handleAuthorizationCallback`, `exchangeCodeForToken`, `fetchUserInfo`, `handleAuthorizationError`, `sendPostRequest`, `sendGetRequest`, `readResponse`, `getOriginalRequestUrl`, `removeParameter`, `escapeHtml`
   - Removed unused variables: `clientSecret`, `tokenEndpoint`, `userInfoEndpoint`
   - Simplified configuration (only needs `clientId`, `tenantId`, `redirectUri`, optional `scope`)

### New Files

1. **`legacy/src/main/java/com/example/legacyapp/filter/AzureADCallbackFilter.java`**
   - Handles OAuth2 callback from Azure AD
   - Validates state parameter (CSRF protection)
   - Exchanges authorization code for tokens
   - Fetches user information from Microsoft Graph
   - Loads authorities from database using `UserAuthorityService`
   - Merges authorities from Azure AD and database
   - Stores authentication state in session with standardized keys
   - Sets `LEGACY_AUTH` cookie for session persistence
   - Redirects to home page after successful authentication

2. **`legacy/src/main/java/com/example/legacyapp/service/UserAuthorityService.java`**
   - Interface for loading user authorities from database
   - Single method: `loadAuthoritiesByUsername(String username)`

3. **`legacy/src/main/java/com/example/legacyapp/service/UserAuthorityServiceImpl.java`**
   - JDBC-based implementation (Java 6 compatible)
   - Loads authorities from database tables
   - Configured via environment variables
   - Fails gracefully if database is not configured

## Configuration

### web.xml Configuration

Add both filters to your `web.xml`:

```xml
<!-- Azure AD OAuth2 Filter - Check authentication -->
<filter>
    <filter-name>AzureADOAuth2Filter</filter-name>
    <filter-class>com.example.legacyapp.filter.AzureADOAuth2Filter</filter-class>
    
    <!-- Azure AD Configuration -->
    <init-param>
        <param-name>azureAd.clientId</param-name>
        <param-value>your-client-id</param-value>
    </init-param>
    
    <init-param>
        <param-name>azureAd.clientSecret</param-name>
        <param-value>your-client-secret</param-value>
    </init-param>
    
    <init-param>
        <param-name>azureAd.tenantId</param-name>
        <param-value>your-tenant-id</param-value>
    </init-param>
    
    <init-param>
        <param-name>azureAd.redirectUri</param-name>
        <param-value>http://localhost:8080/yourapp/login/oauth2/code/azure</param-value>
    </init-param>
    
    <init-param>
        <param-name>azureAd.scope</param-name>
        <param-value>openid profile email</param-value>
    </init-param>
</filter>

<!-- Azure AD Callback Filter - Handle OAuth2 callback -->
<filter>
    <filter-name>AzureADCallbackFilter</filter-name>
    <filter-class>com.example.legacyapp.filter.AzureADCallbackFilter</filter-class>
    
    <!-- Same Azure AD Configuration -->
    <init-param>
        <param-name>azureAd.clientId</param-name>
        <param-value>your-client-id</param-value>
    </init-param>
    
    <init-param>
        <param-name>azureAd.clientSecret</param-name>
        <param-value>your-client-secret</param-value>
    </init-param>
    
    <init-param>
        <param-name>azureAd.tenantId</param-name>
        <param-value>your-tenant-id</param-value>
    </init-param>
    
    <init-param>
        <param-name>azureAd.redirectUri</param-name>
        <param-value>http://localhost:8080/yourapp/login/oauth2/code/azure</param-value>
    </init-param>
    
    <init-param>
        <param-name>azureAd.scope</param-name>
        <param-value>openid profile email</param-value>
    </init-param>
</filter>

<!-- Filter Mappings -->
<!-- Callback filter must be mapped ONLY to the callback path -->
<filter-mapping>
    <filter-name>AzureADCallbackFilter</filter-name>
    <url-pattern>/login/oauth2/code/azure</url-pattern>
</filter-mapping>

<!-- OAuth2 filter must be mapped to all paths -->
<filter-mapping>
    <filter-name>AzureADOAuth2Filter</filter-name>
    <url-pattern>/*</url-pattern>
    <dispatcher>REQUEST</dispatcher>
    <dispatcher>FORWARD</dispatcher>
</filter-mapping>
```

**Important**: The `AzureADCallbackFilter` mapping must come BEFORE the `AzureADOAuth2Filter` mapping to ensure callbacks are handled correctly.

### Database Configuration (Optional)

Configure database connection via environment variables:

- `DB_URL` - JDBC connection URL (e.g., `jdbc:mysql://localhost:3306/legacy_db`)
- `DB_USERNAME` - Database username
- `DB_PASSWORD` - Database password
- `DB_DRIVER` - JDBC driver class (default: `com.mysql.jdbc.Driver`)

### Database Schema

Create the following tables for authority management:

```sql
-- Authorities table
CREATE TABLE authorities (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    authority_name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_authority_name (authority_name)
);

-- User authorities table
CREATE TABLE user_authorities (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL,
    authority_id BIGINT NOT NULL,
    active BOOLEAN DEFAULT true,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (authority_id) REFERENCES authorities(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_authority (username, authority_id),
    INDEX idx_username (username),
    INDEX idx_active (active)
);

-- Sample data
INSERT INTO authorities (authority_name, description) VALUES
    ('ROLE_ADMIN', 'Administrator role with full access'),
    ('ROLE_USER', 'Standard user role'),
    ('PERMISSION_READ', 'Read permission for resources'),
    ('PERMISSION_WRITE', 'Write permission for resources'),
    ('FEATURE_REPORTS', 'Access to reporting features');

-- Assign authorities to users (use email addresses from Azure AD)
INSERT INTO user_authorities (username, authority_id, active) VALUES
    ('admin@example.com', 1, true),  -- ROLE_ADMIN
    ('admin@example.com', 4, true),  -- PERMISSION_WRITE
    ('user@example.com', 2, true),   -- ROLE_USER
    ('user@example.com', 3, true);   -- PERMISSION_READ
```

## Authentication Flow

1. User accesses protected resource (e.g., `/`)
2. `AzureADOAuth2Filter` checks authentication:
   - Checks session for `oauth2_access_token`
   - Checks cookies for `LEGACY_AUTH=true`
   - If not authenticated, redirects to Azure AD
3. User authenticates at Azure AD
4. Azure AD redirects to `/login/oauth2/code/azure` with authorization code
5. `AzureADCallbackFilter` handles callback:
   - Validates state (CSRF protection)
   - Exchanges code for tokens
   - Fetches user info from Microsoft Graph
   - Loads authorities from database
   - Merges authorities
   - Stores everything in session
   - Sets `LEGACY_AUTH` cookie
   - Redirects to `/`
6. User accesses `/` again
7. `AzureADOAuth2Filter` finds authentication state, allows access

## Backward Compatibility

- Database authority lookup is optional - the application works without it
- If database is not configured, `UserAuthorityServiceImpl` returns empty authority list
- Cookie fallback ensures authentication persists across requests
- Session keys are standardized with `oauth2_` prefix

## Testing Checklist

- [ ] Verify no redirect loop after authentication
- [ ] Confirm user authorities are loaded from database
- [ ] Check that `LEGACY_AUTH` cookie is set after authentication
- [ ] Test authentication persistence across multiple requests
- [ ] Verify excluded paths don't require authentication
- [ ] Test error handling when database is not configured
- [ ] Confirm CSRF protection works (invalid state parameter rejected)

## Dependencies

Required libraries:
- Servlet API 3.1+ (javax.servlet)
- JSON library (org.json)
- JDBC driver (e.g., MySQL Connector/J)

## Java 6 Compatibility

All code is written using Java 6 compatible syntax:
- No try-with-resources (manual resource closing)
- No lambda expressions
- No method references
- No diamond operator
- Manual iteration instead of forEach

## Security Considerations

1. **CSRF Protection**: State parameter validates callback requests
2. **HttpOnly Cookie**: Prevents JavaScript access to authentication cookie
3. **Secure Cookie**: Should be enabled in production (HTTPS required)
4. **Session Security**: Tokens stored in server-side session only
5. **Database Access**: Uses parameterized queries to prevent SQL injection

## Troubleshooting

### Redirect Loop Still Occurring

- Verify both filters are configured in web.xml
- Check filter mapping order (callback filter before OAuth2 filter)
- Ensure callback path `/login/oauth2/code/azure` matches Azure AD configuration
- Verify session keys are standardized with `oauth2_` prefix

### Database Authorities Not Loading

- Check environment variables: `DB_URL`, `DB_USERNAME`, `DB_PASSWORD`
- Verify database tables exist with correct schema
- Check console logs for database connection errors
- Ensure JDBC driver is in classpath

### Cookie Not Being Set

- Verify `AzureADCallbackFilter` is handling the callback
- Check that redirect to home page occurs after authentication
- Ensure cookie is HttpOnly and Secure flags are appropriate for environment
- Check browser developer tools for cookie presence

## Future Enhancements

1. Proper JWT token validation (decode and verify signature)
2. Extract roles from Azure AD ID token claims
3. Token refresh logic using refresh token
4. Logout functionality (clear session and cookie)
5. Connection pooling for database access
6. Caching of database authorities
7. Admin interface for managing authorities
