package com.bibibiu.oauthserver.adapter.secondary.persistence.jpa;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @author arthurmita
 * created 12/07/2020 at 13:33
 **/
@Repository
public interface UserEntityRepository extends JpaRepository<UserEntity, Long> {

    Boolean existsByUserId(String userId);

    Optional<UserEntity> findByUserId(String userId);

    Optional<UserEntity> findByUsername(String username);

    Optional<UserEntity> findByPhoneNumber(String phoneNumber);

    Boolean existsByUsername(String username);
}
