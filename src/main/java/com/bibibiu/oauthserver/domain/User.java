package com.bibibiu.oauthserver.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import ke.co.dynamodigital.commons.models.base.BaseModel;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.Singular;
import lombok.experimental.SuperBuilder;
import one.util.streamex.StreamEx;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.validation.constraints.AssertTrue;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;

/**
 * @author arthurmita
 * created 14/07/2021 at 23:52
 **/
@Data
@NoArgsConstructor
@SuperBuilder(toBuilder = true)
@EqualsAndHashCode(callSuper = false)
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
public class User extends BaseModel implements UserDetails {

    private String userId;

    @Email
    @NotBlank
    private String username;

    @NotBlank
    private String password;

    @NotBlank
    private String phoneNumber;

    @Builder.Default
    private boolean enabled = true;

    @Builder.Default
    private boolean accountNonExpired = true;

    @Builder.Default
    private boolean credentialsNonExpired = true;

    @Builder.Default
    private boolean accountNonLocked = true;

    @Singular
    @NotEmpty(message = "User must at least have one authority")
    private Set<SimpleGrantedAuthority> authorities;

    public Set<SimpleGrantedAuthority> getAuthorities() {
        return Collections.unmodifiableSet(this.authorities);
    }

    public enum Authority {
        CUSTOMER_CARE, ADMIN, SUPER_ADMIN, USER
    }

    @JsonIgnore
    @AssertTrue(message = "User has invalid authorities")
    boolean isAuthoritiesValid() {
        var authorities = StreamEx.of(Authority.values()).map(Authority::name).toImmutableSet();
        return StreamEx.of(this.authorities)
                .map(SimpleGrantedAuthority::getAuthority).remove(authorities::contains)
                .findAny()
                .isEmpty();

    }
}
