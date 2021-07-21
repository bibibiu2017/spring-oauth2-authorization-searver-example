package com.bibibiu.oauthserver.adapter.secondary.persistence.jpa;

import com.bibibiu.oauthserver.application.port.out.client.SaveClientJpaPort;
import ke.co.dynamodigital.commons.annotations.PersistenceAdapter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * @author arthurmita
 * created 14/07/2021 at 23:20
 **/
@PersistenceAdapter
@RequiredArgsConstructor
class ClientEntityPersistenceAdapter implements SaveClientJpaPort {

    private final RegisteredClientRepository repository;

    @Override
    public RegisteredClient save(CreateRegisteredClientCommand command) {
        var client = command.getClient();
        repository.save(client);
        return repository.findById(client.getId());
    }
}
