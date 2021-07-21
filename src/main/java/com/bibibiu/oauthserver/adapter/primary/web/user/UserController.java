package com.bibibiu.oauthserver.adapter.primary.web.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author arthurmita
 * created 20/07/2021 at 20:24
 **/
@RestController
@RequiredArgsConstructor
@RequestMapping("/v1/users")
class UserController {

    @GetMapping("/user-info")
    @PreAuthorize("hasAuthority('SCOPE_openid')")
    UserResponse userInfo(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
        return UserResponse.builder()
                .phoneNumber(principal.getAttribute("phone_number"))
                .userId(principal.getAttribute("user_id"))
                .username(principal.getName())
                .authorities(principal.getAuthorities())
                .build();
    }
}
