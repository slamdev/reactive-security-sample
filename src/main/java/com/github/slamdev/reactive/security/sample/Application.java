package com.github.slamdev.reactive.security.sample;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMessage;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.annotation.PostConstruct;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.Arrays.asList;
import static java.util.UUID.randomUUID;
import static java.util.stream.Collectors.toSet;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.security.config.web.server.SecurityWebFiltersOrder.HTTP_BASIC;

@Slf4j
@SpringBootApplication
@RestController
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    private RoleHierarchy roleHierarchy;

    @PreAuthorize("hasRole('ROLE_ANONYMOUS')")
    @GetMapping("anonymous")
    public Mono<Principal> anonymous(Mono<Principal> principal) {
        log.info("anonymous called");
        return principal;
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping("user")
    public Mono<Principal> user(Mono<Principal> principal) {
        log.info("user called");
        return principal;
    }

    @PostConstruct
    public void init() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy(""
                + "ROLE_ADMIN > ROLE_USER\n"
                + "ROLE_USER > ROLE_ANONYMOUS\n"
                + "ROLE_CUSTOMER > ROLE_ANONYMOUS\n"
        );
        this.roleHierarchy = roleHierarchy;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        AuthenticationWebFilter filter = new AuthenticationWebFilter(this::authenticate);
        filter.setAuthenticationConverter(this::toAuthentication);
        return http
                .csrf().disable()
                .addFilterAt(filter, HTTP_BASIC)
                .authorizeExchange().anyExchange().permitAll()
                .and().build();
    }

    private Mono<Authentication> toAuthentication(ServerWebExchange exchange) {
        log.info("toAuthentication {}", exchange);
        return Mono.fromCallable(exchange::getRequest)
                .map(HttpMessage::getHeaders)
                .flatMap(headers -> Mono.justOrEmpty(headers.getFirst(AUTHORIZATION)))
                .map(header -> new UsernamePasswordAuthenticationToken(header, ""))
                .cast(Authentication.class)
                .switchIfEmpty(Mono.fromCallable(() -> new AnonymousAuthenticationToken(randomUUID().toString(), "anonymous", authorities("anonymous"))));
    }

    private Mono<Authentication> authenticate(Authentication authentication) {
        log.info("authenticate {}", authentication);
        return Mono.just(authentication)
                .filter(Authentication::isAuthenticated)
                .switchIfEmpty(
                        Mono.just(authentication)
                                .filter(a -> asList("user", "admin", "customer").contains(a.getPrincipal().toString()))
                                .switchIfEmpty(Mono.error(new BadCredentialsException("Invalid token")))
                                .map(a -> new UsernamePasswordAuthenticationToken(a.getPrincipal(), a.getCredentials(), authorities(a.getPrincipal().toString())))
                );
    }

    private Set<GrantedAuthority> authorities(String... names) {
        Set<SimpleGrantedAuthority> authorities = Stream.of(names)
                .map(String::toUpperCase)
                .map("ROLE_"::concat)
                .map(SimpleGrantedAuthority::new)
                .collect(toSet());
        return new HashSet<>(roleHierarchy.getReachableGrantedAuthorities(authorities));
    }
}
