package com.innoboard.authservice.service.impl;

import com.innoboard.authservice.client.UserClient;
import com.innoboard.authservice.config.JwtProperties;
import com.innoboard.authservice.domain.Credential;
import com.innoboard.authservice.domain.Role;
import com.innoboard.authservice.dto.CreateUserRequest;
import com.innoboard.authservice.dto.CredentialResponse;
import com.innoboard.authservice.dto.CurrentUserResponse;
import com.innoboard.authservice.dto.LoginRequest;
import com.innoboard.authservice.dto.RefreshTokenRequest;
import com.innoboard.authservice.dto.RegisterCredentialsRequest;
import com.innoboard.authservice.dto.TokenResponse;
import com.innoboard.authservice.exception.AuthCredentialsNotFoundException;
import com.innoboard.authservice.exception.DuplicateCredentialsException;
import com.innoboard.authservice.exception.InvalidTokenException;
import com.innoboard.authservice.mapper.CredentialMapper;
import com.innoboard.authservice.repository.CredentialRepository;
import com.innoboard.authservice.security.AuthUser;
import com.innoboard.authservice.security.JwtService;
import com.innoboard.authservice.service.AuthService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private static final String USERNAME_UNIQUE_CONSTRAINT = "uq_credentials_username";

    private final CredentialRepository repository;
    private final CredentialMapper mapper;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final UserClient userClient;
    private final TransactionTemplate transactionTemplate;

    @Override
    public CredentialResponse register(RegisterCredentialsRequest request) {
        if (repository.existsByUsername(request.login())) {
            throw new DuplicateCredentialsException("Login already taken: " + request.login());
        }

        String passwordHash = passwordEncoder.encode(request.password());

        Long userId = userClient.createUser(new CreateUserRequest(
                request.name(), request.surname(), request.birthDate(), request.email()));

        try {
            return transactionTemplate.execute(status -> {
                Credential credentials = mapper.toEntity(request);
                credentials.setUserId(userId);
                credentials.setPasswordHash(passwordHash);
                credentials.setRole(Role.USER);
                credentials.setActive(true);
                return mapper.toResponse(repository.save(credentials));
            });
        } catch (DataIntegrityViolationException e) {
            compensateUser(userId);
            if (isUsernameUniqueViolation(e)) {
                throw new DuplicateCredentialsException("Login already taken: " + request.login());
            }
            throw e;
        } catch (RuntimeException e) {
            compensateUser(userId);
            throw e;
        }
    }

    @Override
    public TokenResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(request.login(), request.password()));
        if (!(authentication.getPrincipal() instanceof AuthUser user)) {
            throw new IllegalStateException("Unexpected authentication principal");
        }
        return buildTokenResponse(user.userId(), user.role());
    }

    @Override
    public TokenResponse refresh(RefreshTokenRequest request) {
        Long userId;
        try {
            Claims claims = jwtService.parseToken(request.refreshToken());
            if (!JwtService.REFRESH_TOKEN_TYPE.equals(jwtService.extractType(claims))) {
                throw new IllegalArgumentException("Not a refresh token");
            }
            userId = jwtService.extractUserId(claims);
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidTokenException("Invalid refresh token");
        }

        Credential credentials = repository.findByUserId(userId).orElseThrow(
                () -> new InvalidTokenException("Invalid refresh token"));
        if (!credentials.isActive()) {
            throw new InvalidTokenException("Invalid refresh token");
        }
        return buildTokenResponse(userId, credentials.getRole());
    }

    @Override
    @Transactional(readOnly = true)
    public CredentialResponse getCredentials(Long userId) {
        return repository.findByUserId(userId)
                .map(mapper::toResponse)
                .orElseThrow(() -> new AuthCredentialsNotFoundException(userId));
    }

    @Override
    public CurrentUserResponse me(AuthUser user) {
        return new CurrentUserResponse(user.userId(), user.role().name());
    }

    private TokenResponse buildTokenResponse(Long userId, Role role) {
        String accessToken = jwtService.generateAccessToken(userId, role);
        String refreshToken = jwtService.generateRefreshToken(userId, role);
        return new TokenResponse(accessToken, refreshToken, "Bearer",
                jwtProperties.accessTokenTtl().toSeconds());
    }

    private void compensateUser(Long userId) {
        try {
            userClient.deleteUser(userId);
        } catch (RuntimeException rollbackEx) {
            log.error("Failed to delete user {} after failed registration", userId, rollbackEx);
        }
    }

    private boolean isUsernameUniqueViolation(DataIntegrityViolationException e) {
        String details = e.getMostSpecificCause().getMessage();
        if (details == null) {
            details = e.getMessage();
        }
        return details != null && details.contains(USERNAME_UNIQUE_CONSTRAINT);
    }
}
