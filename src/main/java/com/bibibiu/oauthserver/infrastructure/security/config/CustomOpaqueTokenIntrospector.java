package com.bibibiu.oauthserver.infrastructure.security.config;

import com.bibibiu.oauthserver.domain.User;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.bibibiu.oauthserver.infrastructure.security.config.WebConfiguration.*;
import static org.springframework.security.oauth2.core.oidc.OidcScopes.*;

/**
 * @author arthurmita
 * created 20/07/2021 at 23:51
 **/
class CustomOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private final UserDetailsService service;
    private final  OpaqueTokenIntrospector delegate;

    public CustomOpaqueTokenIntrospector(UserDetailsService service, OAuth2ResourceServerProperties properties) {
        this.service = service;
        var opaqueToken = properties.getOpaquetoken();
        var uri = opaqueToken.getIntrospectionUri();
        var clientId = opaqueToken.getClientId();
        var clientSecret = opaqueToken.getClientSecret();
        this.delegate = new NimbusOpaqueTokenIntrospector(uri, clientId, clientSecret);
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2IntrospectionAuthenticatedPrincipal authorized = (OAuth2IntrospectionAuthenticatedPrincipal) delegate.introspect(token);

        if (!authorized.getAudience().contains(RESOURCE))
            throw new BadOpaqueTokenException("Provided token does not have audience(" + RESOURCE +")");

        List<String> scopes = authorized.getClaimAsStringList("scope");
        if (scopes == null || !scopes.contains(OPENID))
            return authorized;

        var user = ((User) service.loadUserByUsername(authorized.getName()));

        List<GrantedAuthority> authorities = new ArrayList<>(authorized.getAuthorities());
        List<GrantedAuthority> roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).map(role -> "ROLE_" + role)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        CollectionUtils.addAll(authorities, roles);

        Map<String, Object> claims = new HashMap<>(authorized.getClaims());
        claims.put("user_id", user.getUserId());
        claims.put("phone_number", user.getPhoneNumber());
        claims.put("created", user.getCreatedOn());
        claims.put("isActive", user.isAccountNonExpired() && user.isCredentialsNonExpired() && user.isAccountNonLocked() && user.isEnabled());

        return new OAuth2IntrospectionAuthenticatedPrincipal(claims, authorities);
    }
}
