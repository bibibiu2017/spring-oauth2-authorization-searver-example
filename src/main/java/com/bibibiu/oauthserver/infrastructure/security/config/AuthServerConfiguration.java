package com.bibibiu.oauthserver.infrastructure.security.config;

import com.bibibiu.oauthserver.domain.User;
import com.bibibiu.oauthserver.infrastructure.security.jose.Jwks;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

/**
 * @author arthurmita
 * created 14/07/2021 at 21:56
 **/
@Configuration(proxyBeanMethods = false)
class AuthServerConfiguration {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(AbstractAuthenticationFilterConfigurer::permitAll).build();
    }


    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate template, RegisteredClientRepository repository) {
        return new CustomJdbcOauth2AuthorizationService(template, repository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate template, RegisteredClientRepository repository) {
        return new JdbcOAuth2AuthorizationConsentService(template, repository);
    }


    @Bean
    public RegisteredClientRepository RegisteredClientRepository(JdbcTemplate template) {
        return new JdbcRegisteredClientRepository(template);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> userCustomizer() {

        return (context) -> {
            enhanceTokenAudience(context);
            if (context.getTokenType().getValue().equals("id_token")) enhanceIdToken(context);
        };
    }

    private void enhanceIdToken(JwtEncodingContext context) {
        if (context.getPrincipal() != null && context.getPrincipal().isAuthenticated())
            if (context.getPrincipal() instanceof UsernamePasswordAuthenticationToken)
                enhanceUserIdToken(context);
    }

    private void enhanceUserIdToken(JwtEncodingContext context) {
        UsernamePasswordAuthenticationToken authentication = context.getPrincipal();
        User user = (User) authentication.getPrincipal();
        context.getClaims().claim("userId", user.getUserId());
    }

    private void enhanceTokenAudience(JwtEncodingContext context) {
        var client = context.getRegisteredClient();

        List<String> resources = client.getClientSettings().setting("resources");

        if (resources == null || resources.isEmpty()) return;

        context.getClaims().audience(resources);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public ProviderSettings providerSettings() {
        return new ProviderSettings().issuer("http://localhost:8000/authorization");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
