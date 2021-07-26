package com.bibibiu.oauthserver.infrastructure.security.config;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;

import static com.bibibiu.oauthserver.infrastructure.security.config.WebConfiguration.*;

/**
 * @author arthurmita
 * created 26/07/2021 at 08:33
 **/
class CustomJwtValidators {

    static AudienceValidator audienceValidator() {
        return new AudienceValidator();
    }

    static OAuth2TokenValidator<Jwt> issuerValidator(String issuerUri) {
        return new JwtIssuerValidator(issuerUri);
    }

    static class AudienceValidator implements OAuth2TokenValidator<Jwt> {

        @Override
        public OAuth2TokenValidatorResult validate(Jwt token) {
            if (token.getAudience().contains(RESOURCE))
                return OAuth2TokenValidatorResult.success();
            var message = "Token does not have required audience(" + RESOURCE + ")";
            OAuth2Error error = new OAuth2Error("access_denied", message, null);
            return OAuth2TokenValidatorResult.failure(error);
        }
    }
}
