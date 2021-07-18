package com.bibibiu.oauthserver.data;

import com.bibibiu.oauthserver.domain.User;
import ke.co.dynamodigital.commons.config.mother.PersistableModelMother;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static com.bibibiu.oauthserver.domain.User.Authority.SUPER_ADMIN;

/**
 * @author arthurmita
 * created 15/07/2021 at 00:05
 **/
public class UserMother extends PersistableModelMother<User> {

    protected UserMother(User child) {
        super(child);
    }

    public static UserMother instance(User user) {
        return new UserMother(user);
    }

    public static UserMother instance() {
        var user = User.builder()
                .authority(new SimpleGrantedAuthority(SUPER_ADMIN.name()))
                .phoneNumber(faker.phoneNumber().phoneNumber())
                .password(faker.internet().password())
                .username(faker.internet().emailAddress())
                .build();
        return instance(user);
    }

    @Override
    public <T extends PersistableModelMother<User>> T merged() {
        this.with(User::setUserId, faker.regexify("([A-Z]|\\d){8}"));
        return super.merged();
    }
}
