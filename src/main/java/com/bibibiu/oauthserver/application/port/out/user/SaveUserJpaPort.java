package com.bibibiu.oauthserver.application.port.out.user;

import com.bibibiu.oauthserver.domain.User;
import com.bibibiu.oauthserver.domain.User.Authority;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Value;
import one.util.streamex.StreamEx;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.validation.Valid;
import javax.validation.constraints.AssertTrue;
import javax.validation.constraints.NotNull;

/**
 * @author arthurmita
 * created 14/07/2021 at 23:56
 **/
public interface SaveUserJpaPort {

    User save(@Valid CreateUserCommand command);

    @Value(staticConstructor = "of")
    class CreateUserCommand {
        @Valid @NotNull User user;
    }
}
