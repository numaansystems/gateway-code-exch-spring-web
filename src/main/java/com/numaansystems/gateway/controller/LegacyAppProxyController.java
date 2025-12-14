package com.numaansystems.gateway.controller;

import jakarta.annotation.PreDestroy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.hc.client5.http.classic.methods.*;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Enumeration;

/**
 * Reverse proxy controller that forwards requests to a legacy application.
 * 
 * <p>This controller intercepts all requests to /myapp/** and forwards them
 * to the configured legacy application URL, preserving HTTP methods, headers,
 * and request bodies.</p>
 * 
 * <h2>Features</h2>
 * <ul>
 *   <li>Supports all HTTP methods (GET, POST, PUT, DELETE, PATCH, etc.)</li>
 *   <li>Copies request headers (except hop-by-hop headers)</li>
 *   <li>Forwards request bodies for POST/PUT/PATCH</li>
 *   <li>Copies response headers and status codes</li>
 *   <li>Uses shared HttpClient instance for connection pooling</li>
 *   <li>Proper resource cleanup with @PreDestroy</li>
 * </ul>
 * 
 * @author Numaan Systems
 * @version 0.1.0
 */
@RestController
@RequestMapping("/myapp")
public class LegacyAppProxyController {

    private static final Logger logger = LoggerFactory.getLogger(LegacyAppProxyController.class);

    @Value("${legacy.app.url:http://localhost:8080}")
    private String legacyAppUrl;

    private final CloseableHttpClient httpClient;

    /**
     * Constructor that initializes the shared HTTP client.
     */
    public LegacyAppProxyController() {
        this.httpClient = HttpClients.createDefault();
        logger.info("LegacyAppProxyController initialized with shared HTTP client");
    }

    /**
     * Cleanup method that closes the HTTP client when the bean is destroyed.
     */
    @PreDestroy
    public void destroy() {
        try {
            httpClient.close();
            logger.info("HTTP client closed successfully");
        } catch (IOException e) {
            logger.error("Error closing HTTP client", e);
        }
    }

    /**
     * Proxy all requests to the legacy application.
     * 
     * @param request the incoming HTTP request
     * @param response the HTTP response to write to
     */
    @RequestMapping("/**")
    public void proxyRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        String queryString = request.getQueryString();

        // Remove context path and /myapp prefix to get the path to forward
        String path = requestUri.substring(contextPath.length() + "/myapp".length());
        
        // Build target URL
        String targetUrl = legacyAppUrl + path;
        if (queryString != null) {
            targetUrl += "?" + queryString;
        }

        logger.debug("Proxying {} {} to {}", request.getMethod(), requestUri, targetUrl);

        try {
            // Create HTTP request based on method
            HttpUriRequestBase proxyRequest = createProxyRequest(request.getMethod(), targetUrl);

            // Copy headers (skip hop-by-hop headers)
            copyRequestHeaders(request, proxyRequest);

            // Copy request body for methods that support it
            if (hasRequestBody(request.getMethod())) {
                long contentLength = request.getContentLength();
                proxyRequest.setEntity(new InputStreamEntity(request.getInputStream(), contentLength, null));
            }

            // Execute the request
            try (CloseableHttpResponse proxyResponse = httpClient.execute(proxyRequest)) {
                // Copy response status
                response.setStatus(proxyResponse.getCode());

                // Copy response headers
                copyResponseHeaders(proxyResponse, response);

                // Copy response body
                if (proxyResponse.getEntity() != null) {
                    byte[] responseBody = EntityUtils.toByteArray(proxyResponse.getEntity());
                    response.getOutputStream().write(responseBody);
                }

                logger.debug("Proxy request completed with status {}", proxyResponse.getCode());
            }
        } catch (Exception e) {
            logger.error("Error proxying request to {}", targetUrl, e);
            response.sendError(HttpServletResponse.SC_BAD_GATEWAY, "Error forwarding request to legacy application");
        }
    }

    /**
     * Creates an HTTP request object based on the method name.
     */
    private HttpUriRequestBase createProxyRequest(String method, String targetUrl) {
        return switch (method.toUpperCase()) {
            case "GET" -> new HttpGet(targetUrl);
            case "POST" -> new HttpPost(targetUrl);
            case "PUT" -> new HttpPut(targetUrl);
            case "DELETE" -> new HttpDelete(targetUrl);
            case "PATCH" -> new HttpPatch(targetUrl);
            case "HEAD" -> new HttpHead(targetUrl);
            case "OPTIONS" -> new HttpOptions(targetUrl);
            default -> new HttpGet(targetUrl); // Fallback to GET
        };
    }

    /**
     * Checks if the HTTP method typically has a request body.
     */
    private boolean hasRequestBody(String method) {
        return "POST".equalsIgnoreCase(method) || 
               "PUT".equalsIgnoreCase(method) || 
               "PATCH".equalsIgnoreCase(method);
    }

    /**
     * Copies request headers from servlet request to HTTP client request.
     * Skips hop-by-hop headers that should not be forwarded.
     */
    private void copyRequestHeaders(HttpServletRequest request, HttpUriRequestBase proxyRequest) {
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            
            // Skip hop-by-hop headers
            if (isHopByHopHeader(headerName)) {
                continue;
            }

            String headerValue = request.getHeader(headerName);
            proxyRequest.setHeader(headerName, headerValue);
        }
    }

    /**
     * Copies response headers from HTTP client response to servlet response.
     * Skips hop-by-hop headers that should not be forwarded.
     */
    private void copyResponseHeaders(CloseableHttpResponse proxyResponse, HttpServletResponse response) {
        for (Header header : proxyResponse.getHeaders()) {
            String headerName = header.getName();
            
            // Skip hop-by-hop headers
            if (isHopByHopHeader(headerName)) {
                continue;
            }

            response.addHeader(headerName, header.getValue());
        }
    }

    /**
     * Checks if a header is a hop-by-hop header that should not be forwarded.
     * These headers are meaningful only for a single transport-level connection.
     */
    private boolean isHopByHopHeader(String headerName) {
        String lowerName = headerName.toLowerCase();
        return lowerName.equals("connection") ||
               lowerName.equals("keep-alive") ||
               lowerName.equals("proxy-authenticate") ||
               lowerName.equals("proxy-authorization") ||
               lowerName.equals("te") ||
               lowerName.equals("trailers") ||
               lowerName.equals("transfer-encoding") ||
               lowerName.equals("upgrade") ||
               lowerName.equals("host"); // Host header should be set by HttpClient
    }
}
