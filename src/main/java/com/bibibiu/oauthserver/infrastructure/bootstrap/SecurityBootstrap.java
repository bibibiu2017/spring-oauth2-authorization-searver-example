package com.bibibiu.oauthserver.infrastructure.bootstrap;

import com.bibibiu.oauthserver.application.port.out.client.SaveClientJpaPort;
import com.bibibiu.oauthserver.application.port.out.client.SaveClientJpaPort.CreateRegisteredClientCommand;
import com.bibibiu.oauthserver.application.port.out.user.SaveUserJpaPort;
import com.bibibiu.oauthserver.application.port.out.user.SaveUserJpaPort.CreateUserCommand;
import com.bibibiu.oauthserver.domain.User;
import ke.co.dynamodigital.commons.utils.LogUtils;
import ke.co.dynamodigital.commons.utils.SecurityUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static com.bibibiu.oauthserver.domain.User.Authority.SUPER_ADMIN;
import static java.util.Collections.unmodifiableList;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.REFRESH_TOKEN;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.BASIC;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.POST;

/**
 * @author arthurmita
 * created 15/07/2021 at 00:32
 **/
@Slf4j
@Configuration
class SecurityBootstrap {

    @Bean
    @Order(1)
    ApplicationRunner userRunner(SaveUserJpaPort port, PasswordEncoder encoder) {
        return args -> {
            var user = User.builder()
                    .phoneNumber("254709279000")
                    .username("support@dynamo.co.ke")
                    .authority(new SimpleGrantedAuthority(SUPER_ADMIN.name()))
                    .password(encoder.encode("Password"))
                    .build();
            try {
                var created = port.save(CreateUserCommand.of(user));
                LogUtils.logObject(log, created, "CreatedUser");
            } catch (Exception e) {
                LogUtils.logError(log, "Could Not Create USer", e.getMessage(), e);
            }
        };
    }


    @Bean
    @Order(2)
    ApplicationRunner clientRunner(SaveClientJpaPort port, PasswordEncoder encoder) {
        return args -> {
            //noinspection RedundantUnmodifiable
            var client = RegisteredClient.withId(SecurityUtils.uuidGenerator())
                    .clientName("UsersClient")
                    .clientId("bibibiu_users_client")
                    .clientSecret(encoder.encode("bibibiu_auth_secret"))
                    .redirectUri("https://www.example.com")
                    .clientAuthenticationMethod(BASIC)
                    .clientAuthenticationMethod(POST)
                    .clientSettings(settings -> settings.requireUserConsent(true).requireProofKey(true))
                    .scopes(scopes -> scopes.addAll(Set.of(OidcScopes.OPENID, "bibibiu_auth:read", "bibibiu_auth:write")))
                    .clientSettings(settings -> settings.setting("resources", unmodifiableList(List.of("bibibiu-auth", "bibibiu-accounts"))))
                    .authorizationGrantTypes(grantTypes -> grantTypes.addAll(Set.of(AUTHORIZATION_CODE, CLIENT_CREDENTIALS, REFRESH_TOKEN)))
                    .tokenSettings(settings -> settings.accessTokenTimeToLive(Duration.ofHours(1)))
                    .tokenSettings(settings -> settings.refreshTokenTimeToLive(Duration.ofHours(24)))
                    .build();
            try {
                var created = port.save(CreateRegisteredClientCommand.of(client));
                LogUtils.logObject(log, created, "Created Client");
            } catch (Exception e) {
                LogUtils.logError(log, "Could Not Create Client", e.getMessage(), e);
            }
        };
    }
}
