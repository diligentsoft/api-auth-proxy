package co.diligentsoft.auth.controller;

import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;

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

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
public class Proxy {

    @Value("${api-auth-proxy.host}")
    private String selfHost;

    @Value("${api-auth-proxy.forward-signing.enabled}")
    private boolean forwardSigningEnabled;

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
     */
    private ResponseEntity<String> handleForwardProxyMode(RequestEntity request, HttpServletRequest servletRequest) {
        log.info("Forward proxying request to host {} for {}", request.getHeaders().getHost().getHostName(), servletRequest.getRemoteAddr());

        HttpHeaders newHeaders = new HttpHeaders();
        newHeaders.add("X-Forwarded-For", servletRequest.getRemoteAddr());

        if (forwardSigningEnabled) {
            final String accessToken = getAccessToken().getValue();
            newHeaders.add(HttpHeaders.AUTHORIZATION, String.format("Bearer %s", accessToken));
        }

        final RequestEntity forwardRequest = requestEntity(request, newHeaders, request.getUrl());
        return restTemplate.exchange(forwardRequest, String.class);
    }

    /**
     * Ensures Authorisation in request
     */
    private ResponseEntity<String> handleReverseProxyMode(RequestEntity request, HttpServletRequest servletRequest) {
        log.info("Reverse proxying request to host {} for {}", request.getHeaders().getHost().getHostName(), servletRequest.getRemoteAddr());

        if (accessTokenValid(request)) {
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

    @SneakyThrows
    private AccessToken getAccessToken() {
        final HTTPResponse response = new TokenRequest(
            URI.create("http://keycloak:8080/auth/realms/development/protocol/openid-connect/token"),
            new ClientSecretPost(new ClientID("oauth-client"), new Secret("**********")),
            new ClientCredentialsGrant()
        ).toHTTPRequest().send();
        final TokenResponse tokenResponse = TokenResponse.parse(response);
        if (tokenResponse.indicatesSuccess()) {
            log.info("Successfully got access token");
            return tokenResponse.toSuccessResponse().getTokens().getAccessToken();
        } else {
            final ErrorObject errorObject = tokenResponse.toErrorResponse().getErrorObject();
            final String errorMsg = String.format("Error when getting access token; error code is %s with description %s", errorObject.getCode(),
                errorObject.getDescription());
            log.error(errorMsg);
            throw new RuntimeException(errorMsg);
        }
    }

    @SneakyThrows
    private boolean accessTokenValid(RequestEntity request) {

        final Optional<String> accessToken = Optional.ofNullable(request.getHeaders().get(HttpHeaders.AUTHORIZATION))
            .map(headerValues -> headerValues.get(0).replace("Bearer ", ""));

        // Create a JWT processor for the access tokens
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
            new DefaultJWTProcessor<>();

        // Set the required "typ" header "at+jwt" for access tokens issued by the
        // Connect2id server, may not be set by other servers
        jwtProcessor.setJWSTypeVerifier(
            new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("JWT")));

        // The public RSA keys to validate the signatures will be sourced from the
        // OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
        // object caches the retrieved keys to speed up subsequent look-ups and can
        // also handle key-rollover
        JWKSource<SecurityContext> keySource =
            new RemoteJWKSet<>(new URL("http://keycloak:8080/auth/realms/development/protocol/openid-connect/certs"));

        // The expected JWS algorithm of the access tokens (agreed out-of-band)
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        // Configure the JWT processor with a key selector to feed matching public
        // RSA keys sourced from the JWK set URL
        JWSKeySelector<SecurityContext> keySelector =
            new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);

        jwtProcessor.setJWSKeySelector(keySelector);

        // Set the required JWT claims for access tokens issued by the Connect2id
        // server, may differ with other servers
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
            new JWTClaimsSet.Builder().issuer("http://keycloak:8080/auth/realms/development").build(),
            new HashSet<>(Arrays.asList("sub", "iat", "exp", "scope", "clientId", "jti"))));

        // Process the token
        SecurityContext ctx = null; // optional context parameter, not required here
        JWTClaimsSet claimsSet = jwtProcessor.process(accessToken.get(), ctx);

        // Print out the token claims set
        System.out.println(claimsSet.toJSONObject());

        return accessToken.isPresent();
    }
}
