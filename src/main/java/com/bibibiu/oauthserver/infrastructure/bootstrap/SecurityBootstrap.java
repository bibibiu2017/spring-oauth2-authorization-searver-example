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
import java.util.List;
import java.util.Set;

import static com.bibibiu.oauthserver.domain.User.Authority.*;
import static java.util.Collections.*;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.*;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.*;

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
            try {
                List.of(webClient(encoder),authServerClient(encoder)).stream()
                        .map(client -> port.save(CreateRegisteredClientCommand.of(client)))
                        .forEach(client -> LogUtils.logObject(log, client, "Created Client"));
            } catch (Exception e) {
                LogUtils.logError(log, "Could Not Create Client", e.getMessage(), e);
            }
        };
    }

    private RegisteredClient webClient(PasswordEncoder encoder) {
        // noinspection deprecation,RedundantUnmodifiable
        return RegisteredClient.withId(SecurityUtils.uuidGenerator())
                .clientName("Game Redux Web")
                .clientId("game_redux_web_client")
                .clientSecret(encoder.encode("bibibiu_auth_secret"))
                .redirectUri("https://www.example.com")
                .clientAuthenticationMethod(BASIC)
                .clientAuthenticationMethod(POST)
                .clientSettings(settings -> settings.requireUserConsent(true).requireProofKey(true))
                .scopes(scopes -> scopes.addAll(Set.of(OidcScopes.OPENID, "user.read", "user.write", "account.read")))
                .clientSettings(settings -> settings.setting("resources", unmodifiableList(List.of("game-redux-auth", "game-redux-accounts"))))
                .authorizationGrantTypes(grantTypes -> grantTypes.addAll(Set.of(AUTHORIZATION_CODE, REFRESH_TOKEN)))
                .tokenSettings(settings -> settings.accessTokenTimeToLive(Duration.ofMinutes(30)))
                .tokenSettings(settings -> settings.refreshTokenTimeToLive(Duration.ofHours(24)))
                .build();
    }

    private RegisteredClient authServerClient(PasswordEncoder encoder) {
        // noinspection deprecation,RedundantUnmodifiable
        return RegisteredClient.withId(SecurityUtils.uuidGenerator())
                .clientName("Game Redux Auth Server")
                .clientId("game_redux_auth_client")
                .clientSecret(encoder.encode("secret"))
                .clientAuthenticationMethod(BASIC)
                .scopes(scopes -> scopes.addAll(Set.of("account.read", "account.write")))
                .clientSettings(settings -> settings.setting("resources", unmodifiableList(List.of("game-redux-accounts"))))
                .authorizationGrantTypes(grantTypes -> grantTypes.addAll(Set.of(CLIENT_CREDENTIALS)))
                .tokenSettings(settings -> settings.accessTokenTimeToLive(Duration.ofDays(1)))
                .build();
    }
}
