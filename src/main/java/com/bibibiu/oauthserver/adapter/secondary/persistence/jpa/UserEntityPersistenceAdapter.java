package com.bibibiu.oauthserver.adapter.secondary.persistence.jpa;

import com.bibibiu.oauthserver.application.port.out.user.SaveUserJpaPort;
import com.bibibiu.oauthserver.domain.User;
import ke.co.dynamodigital.commons.annotations.PersistenceAdapter;
import ke.co.dynamodigital.commons.models.base.BasePersistenceAdapter;
import ke.co.dynamodigital.commons.utils.IDUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.*;
import org.springframework.security.core.userdetails.*;

/**
 * @author arthurmita
 * created 15/07/2021 at 00:16
 **/
@PersistenceAdapter
@RequiredArgsConstructor
@CacheConfig(cacheNames = "users")
class UserEntityPersistenceAdapter extends BasePersistenceAdapter<User, UserEntity, UserEntityRepository>
        implements SaveUserJpaPort, UserDetailsService {

    @Override
    @CachePut(key = "#command.user.username")
    public User save(CreateUserCommand command) {
        return super.create(command.getUser()).map(this::generateUserId)
                .orElseThrow();
    }

    @Override
    protected boolean exists(User toCheck) {
        return repository.existsByUsername(toCheck.getUsername());
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return repository.findByUsername(username)
                .map(super::mapToModel)
                .orElseThrow(() -> new UsernameNotFoundException("User with username(" + username + ") not found"));
    }

    private User generateUserId(User user) {
        var userId = IDUtils.generateUserId(user.getId());
        user.setUserId(userId);
        return super.update(user).orElseThrow();
    }
}
