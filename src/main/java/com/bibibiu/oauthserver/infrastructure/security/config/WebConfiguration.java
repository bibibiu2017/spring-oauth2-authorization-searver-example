package com.bibibiu.oauthserver.infrastructure.security.config;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author arthurmita
 * created 14/07/2021 at 21:44
 **/
@EnableWebSecurity
class WebConfiguration {

    @Bean
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
    OpaqueTokenIntrospector introspector(UserDetailsService service, OAuth2ResourceServerProperties properties) {
        return new UserInfoOpaqueTokenIntrospector(service, properties);
    }

}
