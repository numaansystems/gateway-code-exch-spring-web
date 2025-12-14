# Testing Guide

This guide provides test scripts for verifying the OAuth flow and reverse proxy functionality of the Azure AD Gateway.

## Prerequisites

- Git Bash (Windows) or Bash shell (Linux/Mac)
- curl (usually pre-installed)
- Access to Azure AD tenant (for OAuth testing)

## Environment Variables

Set the following environment variables before testing:

```bash
export AZURE_CLIENT_ID="your-azure-client-id"
export AZURE_CLIENT_SECRET="your-azure-client-secret"
export AZURE_TENANT_ID="your-azure-tenant-id"
export LEGACY_APP_URL="http://localhost:8080"  # Optional: default is localhost:8080
```

## Starting the Gateway

```bash
# Build the application
mvn clean package -DskipTests

# Run the application
java -jar target/gateway-0.1.0.jar
```

The gateway will start on `http://localhost:9090/gateway`

## Test Scripts

### 1. Test Public Endpoint

This endpoint should be accessible without authentication.

```bash
curl -i http://localhost:9090/gateway/test/public
```

**Expected Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "endpoint": "/test/public",
  "access": "public",
  "message": "This endpoint is accessible without authentication",
  "timestamp": 1234567890
}
```

### 2. Test Protected Endpoint

This endpoint requires authentication but should return 200 even without auth (just shows unauthenticated status).

```bash
curl -i http://localhost:9090/gateway/test/protected
```

**Expected Response (without authentication):**
```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "endpoint": "/test/protected",
  "access": "protected",
  "message": "This endpoint requires authentication",
  "authenticated": false,
  "timestamp": 1234567890
}
```

### 3. Test Health Endpoint

```bash
curl -i http://localhost:9090/gateway/auth/health
```

**Expected Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "UP",
  "service": "azure-ad-gateway",
  "version": "1.0.0",
  "activeTokens": 0
}
```

### 4. Test OAuth Flow (Interactive)

Open your browser and navigate to:

```
http://localhost:9090/gateway/test/callback-test
```

This will open an interactive test page where you can:
1. Start the OAuth flow
2. View the received token
3. Validate the token
4. Test various endpoints

### 5. Test OAuth Initiate (Manual Flow)

Start the OAuth flow by opening this URL in your browser:

```
http://localhost:9090/gateway/auth/initiate?returnUrl=http://localhost:9090/gateway/test/callback-test
```

This will:
1. Redirect to Azure AD login
2. Authenticate with Azure AD
3. Return to the callback with an exchange token

### 6. Test Token Validation

After receiving a token from the OAuth flow, validate it:

```bash
# Replace YOUR_TOKEN_HERE with the actual token
TOKEN="YOUR_TOKEN_HERE"

curl -X POST -i "http://localhost:9090/gateway/auth/validate-token?token=$TOKEN"
```

**Expected Response (valid token):**
```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "username": "user@example.com",
  "email": "user@example.com",
  "name": "User Name",
  "authorities": ["SCOPE_openid", "SCOPE_profile", "SCOPE_email"]
}
```

**Expected Response (invalid/expired token):**
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "success": false,
  "error": "Invalid or expired token"
}
```

### 7. Test Reverse Proxy to Legacy App

First, start a simple HTTP server to simulate the legacy app:

```bash
# In a separate terminal, create a test server
mkdir -p /tmp/legacy-app
cd /tmp/legacy-app
echo '{"message": "Hello from legacy app", "path": "/"}' > index.json

# Start a simple HTTP server on port 8080
python3 -m http.server 8080
```

Now test the proxy:

```bash
curl -i http://localhost:9090/gateway/myapp/index.json
```

**Expected Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json

{"message": "Hello from legacy app", "path": "/"}
```

### 8. Test Proxy with Different HTTP Methods

```bash
# GET request
curl -i -X GET http://localhost:9090/gateway/myapp/test

# POST request
curl -i -X POST \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}' \
  http://localhost:9090/gateway/myapp/api/endpoint

# PUT request
curl -i -X PUT \
  -H "Content-Type: application/json" \
  -d '{"update": "data"}' \
  http://localhost:9090/gateway/myapp/api/resource/123

# DELETE request
curl -i -X DELETE http://localhost:9090/gateway/myapp/api/resource/123
```

### 9. Test Logout

```bash
# Open in browser (requires active session)
# This will redirect to Azure AD logout
http://localhost:9090/gateway/auth/logout?returnUrl=http://localhost:9090/gateway/
```

### 10. Full OAuth Flow Test Script

Save this as `test-oauth-flow.sh`:

```bash
#!/bin/bash

GATEWAY_URL="http://localhost:9090/gateway"
RETURN_URL="http://localhost:9090/gateway/test/callback-test"

echo "==================================="
echo "OAuth Flow Test Script"
echo "==================================="
echo ""

# Test 1: Public endpoint
echo "Test 1: Testing public endpoint..."
curl -s "$GATEWAY_URL/test/public" | grep -q "public" && echo "✓ PASSED" || echo "✗ FAILED"
echo ""

# Test 2: Health endpoint
echo "Test 2: Testing health endpoint..."
curl -s "$GATEWAY_URL/auth/health" | grep -q "UP" && echo "✓ PASSED" || echo "✗ FAILED"
echo ""

# Test 3: Protected endpoint (without auth)
echo "Test 3: Testing protected endpoint (without auth)..."
curl -s "$GATEWAY_URL/test/protected" | grep -q "authenticated" && echo "✓ PASSED" || echo "✗ FAILED"
echo ""

# Test 4: OAuth initiate (prints URL)
echo "Test 4: OAuth flow initiation URL:"
echo "$GATEWAY_URL/auth/initiate?returnUrl=$(echo -n "$RETURN_URL" | od -An -tx1 | tr ' ' % | tr -d '\n')"
echo ""
echo "Open the URL above in your browser to test the full OAuth flow"
echo ""

echo "==================================="
echo "Basic Tests Complete"
echo "==================================="
```

Make it executable and run:

```bash
chmod +x test-oauth-flow.sh
./test-oauth-flow.sh
```

## Test Scenarios

### Scenario 1: Legacy App Integration

1. Start the legacy app on port 8080
2. Start the gateway on port 9090
3. Access the legacy app through the gateway: `http://localhost:9090/gateway/myapp/`
4. Initiate OAuth flow: `http://localhost:9090/gateway/auth/initiate?returnUrl=http://localhost:9090/gateway/myapp/home.html`
5. After authentication, verify the token is passed to the legacy app
6. Legacy app validates the token via backend call to `/auth/validate-token`

### Scenario 2: Force Re-authentication

```bash
# Open in browser
http://localhost:9090/gateway/auth/initiate?returnUrl=http://localhost:9090/gateway/test/callback-test&forceReauth=true
```

This will force Azure AD to prompt for credentials even if there's an active session.

### Scenario 3: Token Expiry Testing

1. Obtain a token via OAuth flow
2. Wait for 2+ minutes (default TTL)
3. Try to validate the token - should fail with "expired" error

```bash
# Get token from OAuth flow first
TOKEN="your-token-here"

# Validate immediately (should succeed)
curl -X POST "http://localhost:9090/gateway/auth/validate-token?token=$TOKEN"

# Wait 2+ minutes and try again (should fail)
sleep 130
curl -X POST "http://localhost:9090/gateway/auth/validate-token?token=$TOKEN"
```

### Scenario 4: Single-Use Token Testing

1. Obtain a token via OAuth flow
2. Validate the token once (should succeed)
3. Try to validate the same token again (should fail - already used)

```bash
TOKEN="your-token-here"

# First validation (should succeed)
curl -X POST "http://localhost:9090/gateway/auth/validate-token?token=$TOKEN"

# Second validation with same token (should fail - already used)
curl -X POST "http://localhost:9090/gateway/auth/validate-token?token=$TOKEN"
```

## Troubleshooting

### Issue: OAuth redirect fails

**Solution:** Check that the redirect URI is configured in Azure AD:
```
http://localhost:9090/gateway/login/oauth2/code/azure
```

### Issue: Token validation fails immediately

**Possible causes:**
1. Token already used (single-use enforcement)
2. Token expired (TTL = 2 minutes)
3. Invalid token format

**Check logs:**
```bash
tail -f logs/spring.log | grep -i token
```

### Issue: Proxy returns 502 Bad Gateway

**Possible causes:**
1. Legacy app not running
2. Wrong `LEGACY_APP_URL` configuration

**Verify:**
```bash
# Check if legacy app is accessible
curl -i http://localhost:8080/

# Check gateway configuration
curl -i http://localhost:9090/gateway/actuator/env | grep -i legacy
```

### Issue: "No session found" error

**Solution:** This can happen if:
1. Session expired before OAuth callback
2. Cookies not enabled
3. Different domain/port used

**Verify session configuration in application.yml:**
```yaml
server:
  servlet:
    session:
      cookie:
        http-only: true
        secure: false  # Set to true in production with HTTPS
        same-site: lax
```

## Logging

View detailed logs for debugging:

```bash
# View all gateway logs
tail -f logs/spring.log

# View only OAuth-related logs
tail -f logs/spring.log | grep -i oauth

# View token-related logs
tail -f logs/spring.log | grep -i token

# View proxy-related logs
tail -f logs/spring.log | grep -i proxy
```

## Performance Testing

### Test Proxy Performance

```bash
# Install Apache Bench (if not already installed)
# On Windows Git Bash: Download from Apache Lounge
# On Linux: sudo apt-get install apache2-utils

# Run 1000 requests with 10 concurrent connections
ab -n 1000 -c 10 http://localhost:9090/gateway/myapp/
```

### Test Token Creation Performance

```bash
# Multiple OAuth flows (requires manual browser interaction)
# Or use the test endpoints:
ab -n 100 -c 5 http://localhost:9090/gateway/test/public
```

## Security Testing

### Test CSRF Protection

```bash
# CSRF is disabled for token exchange pattern
# Verify by making POST requests without CSRF tokens
curl -X POST http://localhost:9090/gateway/auth/validate-token?token=test
```

### Test Domain Validation

Try to use an unauthorized redirect domain:

```bash
# This should fail and redirect to root
# Open in browser:
http://localhost:9090/gateway/auth/initiate?returnUrl=http://evil.com/steal-tokens
```

### Test Hop-by-Hop Headers

Verify that sensitive headers are not forwarded:

```bash
# Start proxy and check response headers
curl -v http://localhost:9090/gateway/myapp/ 2>&1 | grep -i "connection\|keep-alive\|proxy"
```

## Notes

- All timestamps are in milliseconds (Unix epoch)
- Tokens are UUID v4 format (36 characters)
- Session cookies use SameSite=Lax for CSRF protection
- Default token TTL is 2 minutes (configurable via `gateway.exchange-token.ttl-minutes`)
- Proxy preserves all HTTP methods and headers (except hop-by-hop)
