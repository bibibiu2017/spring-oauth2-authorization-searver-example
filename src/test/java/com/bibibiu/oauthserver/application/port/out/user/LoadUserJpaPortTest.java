package com.bibibiu.oauthserver.application.port.out.user;

import com.bibibiu.oauthserver.application.port.out.user.SaveUserJpaPort.CreateUserCommand;
import com.bibibiu.oauthserver.data.UserMother;
import com.bibibiu.oauthserver.domain.User;
import ke.co.dynamodigital.commons.config.annotations.OutputPortTest;
import ke.co.dynamodigital.commons.config.extension.WithSoftAssertions;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @author arthurmita
 * created 15/07/2021 at 00:40
 **/
@OutputPortTest
class LoadUserJpaPortTest extends WithSoftAssertions {

    @Autowired
    SaveUserJpaPort saveUserJpaPort;

    @Autowired
    UserDetailsService userDetailsService;

    User user;

    @BeforeEach
    void setUp() {
        user = saveUserJpaPort.save(CreateUserCommand.of(UserMother.instance().child()));
    }

    @Test
    @DisplayName("should load user by username and return found user")
    void shouldLoadUserByUsernameAndReturnFoundUser() {
        //given:
        var username = user.getUsername();

        //when:
        var foundUser = userDetailsService.loadUserByUsername(username);

        //then:
        softly.assertThat(foundUser).isNotNull()
                .usingRecursiveComparison()
                .isEqualTo(user);
    }
}
