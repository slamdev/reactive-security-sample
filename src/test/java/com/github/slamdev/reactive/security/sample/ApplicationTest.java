package com.github.slamdev.reactive.security.sample;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = RANDOM_PORT)
public class ApplicationTest {

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @Autowired
    private WebTestClient webClient;

    @Test
    public void should_hit_anonymous_endpoint() {
        webClient.get().uri("/anonymous").accept(APPLICATION_JSON_UTF8)
                .exchange()
                .expectStatus().is2xxSuccessful()
                .expectBody().jsonPath("$.authorities[0].authority").isEqualTo("ROLE_ANONYMOUS");
    }

    @Test
    public void should_hit_anonymous_endpoint_when_header_is_user() {
        webClient.get().uri("/anonymous").accept(APPLICATION_JSON_UTF8).header(AUTHORIZATION, "user")
                .exchange()
                .expectStatus().is2xxSuccessful()
                .expectBody().jsonPath("$.authorities[0].authority").isEqualTo("ROLE_USER");
    }

    @Test
    public void should_hit_user_endpoint_when_header_is_valid() {
        webClient.get().uri("/user").accept(APPLICATION_JSON_UTF8).header(AUTHORIZATION, "user")
                .exchange()
                .expectStatus().is2xxSuccessful()
                .expectBody().jsonPath("$.authorities[0].authority").isEqualTo("ROLE_USER");
    }

    @Test
    public void should_not_hit_user_endpoint_when_header_is_empty() {
        webClient.get().uri("/user").accept(APPLICATION_JSON_UTF8)
                .exchange()
                .expectStatus().isForbidden()
                .expectBody(String.class).isEqualTo("Denied");
    }

    @Test
    public void should_not_hit_user_endpoint_when_header_is_invalid() {
        webClient.get().uri("/user").accept(APPLICATION_JSON_UTF8).header(AUTHORIZATION, "invalid")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody().isEmpty();
    }

    @Test
    public void should_not_hit_user_endpoint_when_header_has_another_role() {
        webClient.get().uri("/user").accept(APPLICATION_JSON_UTF8).header(AUTHORIZATION, "customer")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody(String.class).isEqualTo("Denied");
    }
}
