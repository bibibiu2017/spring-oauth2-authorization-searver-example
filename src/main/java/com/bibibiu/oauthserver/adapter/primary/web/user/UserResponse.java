package com.bibibiu.oauthserver.adapter.primary.web.user;

import com.bibibiu.oauthserver.domain.User.Authority;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.fasterxml.jackson.annotation.JsonProperty.Access.*;
import static java.util.stream.Collectors.*;

/**
 * @author arthurmita
 * created 20/07/2021 at 21:21
 **/
@Getter
@Setter
@SuperBuilder(toBuilder = true)
class UserResponse {
    private String userId;
    private String username;
    private String phoneNumber;
    private Collection<? extends GrantedAuthority> authorities;

    @JsonProperty(access = READ_ONLY)
    List<Authority> getAuthorities() {
        return this.authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .map(role -> role.startsWith("ROLE_") ? role.replaceFirst("ROLE_", "") : role)
                .filter(role -> Set.of(Authority.values()).stream().map(Authority::name).collect(toSet()).contains(role))
                .map(Authority::valueOf)
                .collect(Collectors.toUnmodifiableList());
    }
}
