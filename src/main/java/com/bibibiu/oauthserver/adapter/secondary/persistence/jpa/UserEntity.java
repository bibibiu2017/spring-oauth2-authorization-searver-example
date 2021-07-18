package com.bibibiu.oauthserver.adapter.secondary.persistence.jpa;

import com.fasterxml.jackson.annotation.JsonIgnore;
import ke.co.dynamodigital.commons.models.base.BaseEntity;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import one.util.streamex.StreamEx;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.persistence.AttributeConverter;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.Table;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author arthurmita
 * created 12/07/2020 at 13:04
 **/
@Getter
@Setter
@Entity
@Table(name = "users")
class UserEntity extends BaseEntity {

    @Accessors(chain = true)
    @Column(name = "user_id", unique = true)
    private String userId;

    @Column(name = "username", nullable = false, unique = true, updatable = false)
    private String username;

    @Column(name = "phone_number", nullable = false, unique = true)
    private String phoneNumber;

    @JsonIgnore
    @Column(name = "password", nullable = false)
    private String password;

    @Column(name = "enabled", nullable = false, columnDefinition = "TINYINT")
    private Boolean enabled;

    @Column(name = "account_non_expired", nullable = false, columnDefinition = "TINYINT")
    private Boolean accountNonExpired;

    @Column(name = "credentials_non_locked", nullable = false, columnDefinition = "TINYINT")
    private Boolean credentialsNonExpired;

    @Column(name = "account_non_locked", nullable = false, columnDefinition = "TINYINT")
    private Boolean accountNonLocked;

    @Convert(converter = AuthorityConverter.class)
    @Column(name = "authorities", nullable = false)
    private Set<SimpleGrantedAuthority> authorities = new HashSet<>();

    private static final class AuthorityConverter implements AttributeConverter<Set<SimpleGrantedAuthority>, String> {

        @Override
        public String convertToDatabaseColumn(Set<SimpleGrantedAuthority> attribute) {
            return attribute.stream().map(SimpleGrantedAuthority::getAuthority).collect(Collectors.joining(","));
        }

        @Override
        public Set<SimpleGrantedAuthority> convertToEntityAttribute(String dbData) {
            return StreamEx.of(dbData.split(",")).map(SimpleGrantedAuthority::new).toImmutableSet();
        }
    }
}
