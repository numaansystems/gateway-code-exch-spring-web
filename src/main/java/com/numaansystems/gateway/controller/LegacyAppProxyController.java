package com.numaansystems.gateway.controller;

import jakarta.annotation.PreDestroy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.hc.client5.http.classic.methods.*;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * Reverse proxy controller for legacy application integration.
 * 
 * <p>This controller proxies all requests under /app/** to the legacy application
 * configured via legacy.app.url property. This eliminates CORS issues and enables
 * seamless integration by making everything appear to be on the same domain.</p>
 * 
 * <h2>Architecture</h2>
 * <ul>
 *   <li>Browser accesses: http://localhost:9090/gateway/app/home.html</li>
 *   <li>Gateway proxy forwards to: http://localhost:8080/myapp/home.html</li>
 *   <li>All traffic flows through gateway - same origin from browser perspective</li>
 * </ul>
 * 
 * <h2>Features</h2>
 * <ul>
 *   <li>Proxies all HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)</li>
 *   <li>Copies request headers, query parameters, and request bodies</li>
 *   <li>Copies response headers, status codes, and response bodies</li>
 *   <li>Filters headers that should not be forwarded (Host, Connection, etc.)</li>
 *   <li>Logs all proxy requests for debugging and audit trails</li>
 * </ul>
 * 
 * @author Numaan Systems
 * @version 0.1.0
 */
@Controller
@RequestMapping("/app")
public class LegacyAppProxyController {

    private static final Logger logger = LoggerFactory.getLogger(LegacyAppProxyController.class);

    /**
     * Headers that should not be forwarded from client to target server.
     * These are connection-specific or proxy-specific headers.
     */
    private static final Set<String> EXCLUDED_REQUEST_HEADERS = Set.of(
        "host", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade"
    );

    /**
     * Headers that should not be forwarded from target server to client.
     * These are connection-specific headers that should be regenerated.
     */
    private static final Set<String> EXCLUDED_RESPONSE_HEADERS = Set.of(
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade"
    );

    /**
     * Shared HttpClient instance for all proxy requests.
     * This is thread-safe and reuses connections for better performance.
     */
    private final CloseableHttpClient httpClient;

    @Value("${legacy.app.url:http://localhost:8080/myapp}")
    private String legacyAppUrl;

    /**
     * Constructor that initializes the shared HttpClient.
     */
    public LegacyAppProxyController() {
        this.httpClient = HttpClients.createDefault();
    }

    /**
     * Cleanup method to close the HttpClient when the controller is destroyed.
     * This prevents resource leaks.
     */
    @PreDestroy
    public void cleanup() {
        try {
            if (httpClient != null) {
                httpClient.close();
                logger.info("HttpClient closed successfully");
            }
        } catch (IOException e) {
            logger.warn("Error closing HttpClient: {}", e.getMessage());
        }
    }

    /**
     * Proxies all requests under /app/** to the legacy application.
     * 
     * <p>This method extracts the path after /app, builds the target URL,
     * and forwards the request to the legacy application using Apache HttpClient 5.</p>
     * 
     * @param request the incoming HTTP request
     * @param response the HTTP response to populate
     * @throws IOException if proxy request fails
     */
    @RequestMapping("/**")
    public void proxyRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Extract path after /app
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        String path = requestUri.substring(contextPath.length());
        String targetPath = path.substring("/app".length());
        if (targetPath.isEmpty()) {
            targetPath = "/";
        }

        // Build target URL with query string
        String queryString = request.getQueryString();
        String targetUrl = legacyAppUrl + targetPath;
        if (queryString != null && !queryString.isEmpty()) {
            targetUrl += "?" + queryString;
        }

        logger.debug("Proxying request: {} {} → {}", request.getMethod(), path, targetUrl);

        // Use shared HttpClient to proxy the request
        try {
            ClassicHttpRequest proxyRequest = createProxyRequest(request.getMethod(), targetUrl);

            // Copy request body for methods that support it
            if (hasRequestBody(request.getMethod())) {
                byte[] requestBody = StreamUtils.copyToByteArray(request.getInputStream());
                if (requestBody.length > 0) {
                    ((HttpUriRequestBase) proxyRequest).setEntity(new ByteArrayEntity(requestBody, null));
                }
            }

            // Copy headers (except Host, Connection, etc.)
            copyRequestHeaders(request, proxyRequest);

            // Execute and copy response
            try (CloseableHttpResponse proxyResponse = httpClient.execute(proxyRequest)) {
                response.setStatus(proxyResponse.getCode());
                copyResponseHeaders(proxyResponse, response);

                if (proxyResponse.getEntity() != null) {
                    byte[] responseBody = EntityUtils.toByteArray(proxyResponse.getEntity());
                    response.getOutputStream().write(responseBody);
                    response.getOutputStream().flush();
                }
            }

            logger.debug("Proxy request completed successfully: {} → {}", path, targetUrl);

        } catch (Exception e) {
            logger.error("Proxy request failed: {} → {}: {}", path, targetUrl, e.getMessage(), e);
            response.sendError(HttpServletResponse.SC_BAD_GATEWAY, 
                "Failed to proxy request to legacy application");
        }
    }

    /**
     * Creates an HTTP request object based on the HTTP method.
     * 
     * @param method the HTTP method (GET, POST, PUT, DELETE, etc.)
     * @param targetUrl the target URL to request
     * @return the HTTP request object
     */
    private ClassicHttpRequest createProxyRequest(String method, String targetUrl) {
        return switch (method.toUpperCase()) {
            case "GET" -> new HttpGet(targetUrl);
            case "POST" -> new HttpPost(targetUrl);
            case "PUT" -> new HttpPut(targetUrl);
            case "DELETE" -> new HttpDelete(targetUrl);
            case "PATCH" -> new HttpPatch(targetUrl);
            case "HEAD" -> new HttpHead(targetUrl);
            case "OPTIONS" -> new HttpOptions(targetUrl);
            case "TRACE" -> new HttpTrace(targetUrl);
            default -> new HttpGet(targetUrl); // Fallback to GET
        };
    }

    /**
     * Checks if the HTTP method typically has a request body.
     * 
     * @param method the HTTP method
     * @return true if the method typically has a body
     */
    private boolean hasRequestBody(String method) {
        String upperMethod = method.toUpperCase();
        return upperMethod.equals("POST") || upperMethod.equals("PUT") || 
               upperMethod.equals("PATCH");
    }

    /**
     * Copies HTTP headers from the incoming request to the proxy request.
     * Filters out headers that should not be forwarded.
     * 
     * @param request the incoming HTTP request
     * @param proxyRequest the proxy request to populate
     */
    private void copyRequestHeaders(HttpServletRequest request, ClassicHttpRequest proxyRequest) {
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            
            // Skip excluded headers
            if (EXCLUDED_REQUEST_HEADERS.contains(headerName.toLowerCase())) {
                continue;
            }

            // Copy all values for this header (some headers can have multiple values)
            Enumeration<String> headerValues = request.getHeaders(headerName);
            while (headerValues.hasMoreElements()) {
                String headerValue = headerValues.nextElement();
                proxyRequest.addHeader(headerName, headerValue);
                logger.trace("Copied request header: {} = {}", headerName, headerValue);
            }
        }
    }

    /**
     * Copies HTTP headers from the proxy response to the outgoing response.
     * Filters out headers that should not be forwarded.
     * 
     * @param proxyResponse the proxy response
     * @param response the outgoing HTTP response
     */
    private void copyResponseHeaders(CloseableHttpResponse proxyResponse, HttpServletResponse response) {
        for (Header header : proxyResponse.getHeaders()) {
            String headerName = header.getName();
            
            // Skip excluded headers
            if (EXCLUDED_RESPONSE_HEADERS.contains(headerName.toLowerCase())) {
                continue;
            }

            response.addHeader(headerName, header.getValue());
            logger.trace("Copied response header: {} = {}", headerName, header.getValue());
        }
    }
}
