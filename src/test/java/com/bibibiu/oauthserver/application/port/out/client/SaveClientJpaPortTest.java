package com.bibibiu.oauthserver.application.port.out.client;

import com.bibibiu.oauthserver.application.port.out.client.SaveClientJpaPort.CreateRegisteredClientCommand;
import ke.co.dynamodigital.commons.config.annotations.OutputPortTest;
import ke.co.dynamodigital.commons.config.extension.WithSoftAssertions;
import ke.co.dynamodigital.commons.utils.*;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.*;

import java.time.Duration;
import java.util.Set;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.*;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC;

@Slf4j
@OutputPortTest
class SaveClientJpaPortTest extends WithSoftAssertions {

    @Autowired
    SaveClientJpaPort saveClientJpaPort;

    @Autowired
    RegisteredClientRepository registeredClientRepository;

    RegisteredClient client;

    @BeforeEach
    void setUp() {
        client = RegisteredClient.withId(SecurityUtils.uuidGenerator())
                .clientName("AUTH_CLIENT")
                .clientId("bibibiu_auth_client")
                .clientSecret("bibibiu_auth_secret")
                .redirectUri("https://www.example.com")
                .clientAuthenticationMethod(CLIENT_SECRET_BASIC)
                .clientSettings(settings -> settings.requireUserConsent(true))
                .scopes(scopes -> scopes.addAll(Set.of(OidcScopes.OPENID, "bibibiu_auth:read", "bibibiu_auth:write")))
                .authorizationGrantTypes(grantTypes -> grantTypes.addAll(Set.of(AUTHORIZATION_CODE, CLIENT_CREDENTIALS, REFRESH_TOKEN)))
                .tokenSettings(settings -> settings.accessTokenTimeToLive(Duration.ofHours(1)))
                .tokenSettings(settings -> settings.refreshTokenTimeToLive(Duration.ofHours(24)))
                .build();
    }


    @Test
    @DisplayName("should create registered client and return created client")
    void shouldCreateRegisteredClientAndReturnCreatedClient() {
        //given:
        var command = CreateRegisteredClientCommand.of(client);

        //when:
        var createdClient = saveClientJpaPort.save(command);

        //then:
        softly.assertThat(createdClient).isNotNull()
                .usingRecursiveComparison()
                .ignoringExpectedNullFields()
                .isEqualTo(client);

        //and:
        softly.assertThat(registeredClientRepository.findByClientId(client.getClientId())).isNotNull()
                .usingRecursiveComparison()
                .isEqualTo(createdClient);

        LogUtils.logObject(log, createdClient);
    }
}