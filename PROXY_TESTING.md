# Reverse Proxy Testing Guide

## Overview
The gateway now includes reverse proxy functionality that forwards requests from `/app/**` to the configured legacy application, eliminating CORS issues and enabling seamless integration.

## Configuration

The proxy is configured via the `legacy.app.url` property in `application.yml`:

```yaml
legacy:
  app:
    url: http://localhost:8080/myapp
```

## Testing the Proxy

### Prerequisites
1. A running legacy application at the configured URL (e.g., `http://localhost:8080/myapp`)
2. The gateway application running at `http://localhost:9090/gateway`

### Test Scenarios

#### 1. Basic GET Request
```bash
# Direct access to legacy app
curl http://localhost:8080/myapp/home.html

# Access through gateway proxy
curl http://localhost:9090/gateway/app/home.html

# Both should return the same content
```

#### 2. GET Request with Query Parameters
```bash
# Access through gateway proxy with query string
curl "http://localhost:9090/gateway/app/search?q=test&page=1"

# Should forward to: http://localhost:8080/myapp/search?q=test&page=1
```

#### 3. POST Request with Body
```bash
# POST with JSON body
curl -X POST http://localhost:9090/gateway/app/api/data \
  -H "Content-Type: application/json" \
  -d '{"name":"test","value":123}'

# Should forward the body to: http://localhost:8080/myapp/api/data
```

#### 4. PUT Request
```bash
# PUT request
curl -X PUT http://localhost:9090/gateway/app/api/data/1 \
  -H "Content-Type: application/json" \
  -d '{"name":"updated","value":456}'
```

#### 5. DELETE Request
```bash
# DELETE request
curl -X DELETE http://localhost:9090/gateway/app/api/data/1
```

#### 6. Headers Forwarding
```bash
# Request with custom headers
curl http://localhost:9090/gateway/app/api/status \
  -H "X-Custom-Header: test-value" \
  -H "Accept: application/json"

# Custom headers should be forwarded to the legacy app
```

### Browser Testing

1. Start the legacy application on `http://localhost:8080/myapp`
2. Start the gateway on `http://localhost:9090/gateway`
3. Open browser to: `http://localhost:9090/gateway/app/home.html`
4. Verify:
   - Page loads successfully
   - No CORS errors in browser console
   - Cookies work correctly (check browser DevTools)
   - Subsequent requests use the same session

### Authentication Flow Testing

1. Access a protected page: `http://localhost:9090/gateway/app/protected.html`
2. Legacy app should redirect to: `http://localhost:9090/gateway/auth/initiate?returnUrl=http://localhost:9090/gateway/app/protected.html`
3. Gateway redirects to Azure AD for login
4. After successful login, gateway redirects back to: `http://localhost:9090/gateway/app/protected.html?token=xxx`
5. Legacy app validates token and creates session
6. Protected page displays successfully

## Troubleshooting

### Check Logs
Enable debug logging to see proxy requests:
```yaml
logging:
  level:
    com.numaansystems.gateway.controller.LegacyAppProxyController: DEBUG
```

### Common Issues

1. **502 Bad Gateway** - Legacy app is not running or URL is incorrect
   - Check that legacy app is running at the configured URL
   - Verify `legacy.app.url` in application.yml

2. **Connection Refused** - Network connectivity issue
   - Check firewall rules
   - Verify legacy app port is accessible

3. **Headers Not Forwarded** - Check excluded headers list
   - Review EXCLUDED_REQUEST_HEADERS and EXCLUDED_RESPONSE_HEADERS in LegacyAppProxyController

## Security Considerations

- The `/app/**` endpoints are permitted without gateway authentication
- The legacy application is responsible for its own authentication
- In production, consider:
  - Adding rate limiting
  - Implementing request validation
  - Using HTTPS for all connections
  - Configuring proper CORS origins

## Performance Notes

- The gateway uses a shared HttpClient instance for all proxy requests
- Connection pooling is enabled for better performance
- Consider tuning HttpClient settings for high-traffic scenarios
