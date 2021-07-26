package com.bibibiu.oauthserver.infrastructure.security.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author arthurmita
 * created 14/07/2021 at 21:44
 **/
@EnableWebSecurity
@RequiredArgsConstructor
@Configuration(proxyBeanMethods = false)
class WebConfiguration {

    static final String RESOURCE = "game-redux-auth";

    private final OAuth2ResourceServerProperties properties;

    @Bean
    @Order(2)
    SecurityFilterChain httpSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(req -> {
                    req.antMatchers("/js/**", "/css/**", "/webjars/**", "/img/**").permitAll();
                    req.anyRequest().authenticated();
                })
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken)
                .formLogin(login -> login.loginPage("/login").permitAll());
        return http.build();
    }

    @Bean
    @Order(1)
    SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .antMatcher("/api/**")
                .authorizeRequests(req -> req.anyRequest().authenticated())
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .formLogin(AbstractHttpConfigurer::disable);
        return http.build();
    }

    @Bean
    OpaqueTokenIntrospector introspector(UserDetailsService service) {
        return new CustomOpaqueTokenIntrospector(service, properties);
    }

    @Bean
    JwtDecoder decoder(JWKSource<SecurityContext> jwkSource) {
        var issuerUri = properties.getJwt().getIssuerUri();
        var decoder = (NimbusJwtDecoder) OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);

        var audienceValidator = CustomJwtValidators.audienceValidator();
        var issuerValidator = CustomJwtValidators.issuerValidator(issuerUri);
        var delegateValidator = new DelegatingOAuth2TokenValidator<>(issuerValidator, audienceValidator);

        decoder.setJwtValidator(delegateValidator);
        return decoder;
    }
}
