package com.bibibiu.oauthserver.application.port.out.user;

import com.bibibiu.oauthserver.adapter.secondary.persistence.jpa.UserEntityRepository;
import com.bibibiu.oauthserver.application.port.out.user.SaveUserJpaPort.CreateUserCommand;
import com.bibibiu.oauthserver.data.UserMother;
import com.bibibiu.oauthserver.domain.User;
import ke.co.dynamodigital.commons.config.annotations.OutputPortTest;
import ke.co.dynamodigital.commons.config.extension.WithSoftAssertions;
import ke.co.dynamodigital.commons.utils.LogUtils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;

@Slf4j
@OutputPortTest
class SaveUserJpaPortTest extends WithSoftAssertions {

    @Autowired
    SaveUserJpaPort saveUserJpaPort;

    @Autowired
    UserEntityRepository userEntityRepository;

    User user;

    @BeforeEach
    void setUp() {
        user = UserMother.instance().child();
    }

    @AfterEach
    void tearDown() {
        userEntityRepository.deleteAll();
    }

    @Test
    @DisplayName("should create user and return created user")
    void shouldCreateUserAndReturnCreatedUser() {
        //given:
        var command = CreateUserCommand.of(user);

        //when:
        var createdUser = saveUserJpaPort.save(command);

        //then:
        softly.assertThat(createdUser).isNotNull()
                .usingRecursiveComparison()
                .ignoringExpectedNullFields()
                .isEqualTo(user);

        //and:
        softly.assertThat(userEntityRepository.findByUsername(user.getUsername()))
                .isPresent().get()
                .usingRecursiveComparison()
                .ignoringFields("grantedAuthorities")
                .isEqualTo(createdUser);

        LogUtils.logObject(log, createdUser);
    }

}