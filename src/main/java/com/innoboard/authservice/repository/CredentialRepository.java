package com.innoboard.authservice.repository;

import com.innoboard.authservice.domain.Credential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CredentialRepository extends JpaRepository<Credential, Long> {

    Optional<Credential> findByUsername(String username);

    Optional<Credential> findByUserId(Long userId);

    boolean existsByUsername(String username);
}
