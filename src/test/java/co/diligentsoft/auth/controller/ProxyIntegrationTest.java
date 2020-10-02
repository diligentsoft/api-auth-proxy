package co.diligentsoft.auth.controller;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.UUID;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.SocketUtils;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.deser.std.UUIDDeserializer;
import com.github.tomakehurst.wiremock.junit.WireMockClassRule;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.notMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.DEFINED_PORT;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = DEFINED_PORT)
@ActiveProfiles("test")
public class ProxyIntegrationTest {

    private static int proxyPort = SocketUtils.findAvailableTcpPort();

    @ClassRule
    public static WireMockClassRule protectedResource = new WireMockClassRule(wireMockConfig().dynamicPort());

    @ClassRule
    public static WireMockClassRule externalService = new WireMockClassRule(wireMockConfig().dynamicPort());

    @Autowired
    private RestTemplateBuilder restTemplateBuilder;

    private RestTemplate proxiedRestTemplate;

    private RestTemplate unproxiedRestTemplate;

    @BeforeClass
    public static void setApplicationPropertiesDynamically() {
        System.setProperty("server.port", String.valueOf(proxyPort));
        System.setProperty("api-auth-proxy.resource-protection.baseUrl", protectedResource.baseUrl());
    }

    @Before
    public void configureRestTemplates() {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        var proxy = new java.net.Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", proxyPort));
        requestFactory.setProxy(proxy);

        proxiedRestTemplate = restTemplateBuilder.requestFactory(() -> requestFactory).build();

        unproxiedRestTemplate = restTemplateBuilder.build();
    }

    @Before
    public void setupStubsOnMockServices() {
        protectedResource.stubFor(get(urlEqualTo("/v1/protected-resource"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "text/plain")
                .withBody("Some content from the resource protected by the proxy")));

        externalService.stubFor(get(urlEqualTo("/v1/external-resource"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "text/plain")
                .withBody("Some content from the external resource obtained via the proxy")));
    }

    @Test
    public void shouldReverseProxyProtectedResource() {
        final String url = "http://localhost:" + proxyPort + "/v1/protected-resource";
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, UUID.randomUUID().toString());
        final ResponseEntity<String> response = unproxiedRestTemplate.exchange(
            url, HttpMethod.GET, new HttpEntity<>(headers), String.class
        );

        protectedResource.verify(
            getRequestedFor(urlMatching("/v1/protected-resource"))
        );
    }

    @Test
    public void shouldForwardProxyToExternalService() {
        final ResponseEntity<String> response = proxiedRestTemplate.getForEntity(externalService.baseUrl() + "/v1/external-resource", String.class);

        externalService.verify(
            getRequestedFor(urlMatching("/v1/external-resource"))
            .withHeader("X-Forwarded-For", matching("127.0.0.1"))
            .withHeader("Authorization", notMatching(""))
        );
    }

}
