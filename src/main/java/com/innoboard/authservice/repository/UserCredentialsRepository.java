package com.innoboard.authservice.repository;

import com.innoboard.authservice.domain.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserCredentialsRepository extends JpaRepository<UserCredentials, Long> {

    Optional<UserCredentials> findByLogin(String login);

    Optional<UserCredentials> findByUserId(Long userId);

    boolean existsByLogin(String login);

    boolean existsByUserId(Long userId);
}
