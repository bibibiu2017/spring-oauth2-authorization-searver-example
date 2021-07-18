package com.bibibiu.oauthserver.application.port.out.client;

import lombok.Value;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 * @author arthurmita
 * created 14/07/2021 at 23:03
 **/
public interface SaveClientJpaPort {

    RegisteredClient save(@Valid CreateRegisteredClientCommand command);

    @Value(staticConstructor = "of")
    class CreateRegisteredClientCommand {
        @NotNull RegisteredClient client;
    }
}
