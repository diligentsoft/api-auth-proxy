package co.diligentsoft.auth.controller;

import java.net.URI;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
public class Proxy {

    @Value("${api-auth-proxy.host}")
    private String selfHost;

    @Value("${api-auth-proxy.resource-protection.enabled}")
    private boolean resourceProtectionEnabled;

    @Value("${api-auth-proxy.resource-protection.baseUrl}")
    private URI protectedHostBaseUrl;

    @Autowired
    private RestTemplate restTemplate;

    /**
     * Filters a HTTP request.
     *
     * When the request is for a configured protected resource (host), the filter will act in reverse-proxy mode;
     * the request will be checked by verifying the OAuth access token which should be found within the Authorisation header.
     * Subsequently, any configured authorisation checks will be performed to ensure the client possess the necessary claims
     * to access the protected resource specified in configuration.
     *
     * For all other requests, the filter will act in forward-proxy mode;  the request will be signed by adding
     * an Authorisation header containing an OAuth access token (Bearer token) obtained from the configured OAuth server.
     *
     * @param request
     * @return http response
     */
    @RequestMapping("/**")
    public ResponseEntity<String> proxyRequest(RequestEntity request, HttpServletRequest servletRequest) {
        final ResponseEntity<String> response;
        if (hostWithPort(request).equalsIgnoreCase(selfHost)) {
            if (resourceProtectionEnabled) {
                response = handleReverseProxyMode(request, servletRequest);
            } else {
                response = ResponseEntity.badRequest()
                    .body("Resource protection is not enabled; cannot act in reverse-proxy mode.");
            }
        } else {
            response = handleForwardProxyMode(request, servletRequest);
        }
        return response;
    }

    /**
     * Adds Authorisation to request
     * TODO: Call OAuth server to get access token
     */
    private ResponseEntity<String> handleForwardProxyMode(RequestEntity request, HttpServletRequest servletRequest) {
        log.info("Forward proxying request to host {} for {}", request.getHeaders().getHost().getHostName(), servletRequest.getRemoteAddr());

        HttpHeaders newHeaders = new HttpHeaders();
        newHeaders.add("X-Forwarded-For", servletRequest.getRemoteAddr());
        newHeaders.add(HttpHeaders.AUTHORIZATION, UUID.randomUUID().toString());
        final RequestEntity forwardRequest = requestEntity(request, newHeaders, request.getUrl());
        return restTemplate.exchange(forwardRequest, String.class);
    }

    /**
     * Ensures Authorisation in request
     * TODO: Verify access token is signed by OAuth server and not expired
     */
    private ResponseEntity<String> handleReverseProxyMode(RequestEntity request, HttpServletRequest servletRequest) {
        log.info("Reverse proxying request to host {} for {}", request.getHeaders().getHost().getHostName(), servletRequest.getRemoteAddr());

        if (request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            final RequestEntity forwardRequest = requestEntity(request, HttpHeaders.EMPTY, urlForProtectedResource(request));
            return restTemplate.exchange(forwardRequest, String.class);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    private RequestEntity requestEntity(RequestEntity originalRequest, HttpHeaders additionalHeaders, URI newUrl) {
        return RequestEntity.method(originalRequest.getMethod(), newUrl)
            .headers(originalRequest.getHeaders())
            .headers(additionalHeaders)
            .body(originalRequest.getBody());
    }

    private String hostWithPort(RequestEntity request) {
        return hostWithPort(request.getUrl().getHost(), request.getUrl().getPort());
    }

    private String hostWithPort(String hostname, int port) {
        return hostname + ":" + port;
    }

    private URI urlForProtectedResource(RequestEntity originalRequest) {
        return UriComponentsBuilder.fromUri(originalRequest.getUrl())
            .scheme(protectedHostBaseUrl.getScheme())
            .host(protectedHostBaseUrl.getHost())
            .port(protectedHostBaseUrl.getPort())
            .build()
            .toUri();
    }
}
