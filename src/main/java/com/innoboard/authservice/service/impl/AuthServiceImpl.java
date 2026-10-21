package com.innoboard.authservice.service.impl;

import com.innoboard.authservice.config.JwtProperties;
import com.innoboard.authservice.domain.UserCredentials;
import com.innoboard.authservice.dto.*;
import com.innoboard.authservice.exception.DuplicateCredentialsException;
import com.innoboard.authservice.exception.InvalidTokenException;
import com.innoboard.authservice.exception.UserCredentialsNotFoundException;
import com.innoboard.authservice.mapper.UserCredentialsMapper;
import com.innoboard.authservice.repository.UserCredentialsRepository;
import com.innoboard.authservice.security.JwtService;
import com.innoboard.authservice.service.AuthService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.validation.ValidationException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserCredentialsRepository repository;
    private final UserCredentialsMapper mapper;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;

    @Override
    @Transactional
    public UserCredentialsResponse register(RegisterCredentialsRequest request){
        if (repository.existsByLogin(request.login())){
            throw new DuplicateCredentialsException("Login already taken: " + request.login());
        }
        if (repository.existsByUserId(request.userId())) {
            throw new DuplicateCredentialsException("Credentials already exist for user id: " + request.userId());
        }

        UserCredentials credentials = new UserCredentials();
        credentials.setUserId(request.userId());
        credentials.setLogin(request.login());
        credentials.setPasswordHash(passwordEncoder.encode(request.password()));
        credentials.setRole(request.role());
        credentials.setActive(true);

        UserCredentials saved = repository.save(credentials);
        return mapper.toResponse(saved);
    }

    @Override
    @Transactional(readOnly = true)
    public TokenResponse login (LoginRequest request){
        authenticationManager.authenticate(UsernamePasswordAuthenticationToken
                .unauthenticated(request.login(), request.password()));

        UserCredentials credentials = repository.findByLogin(request.login()).orElseThrow(
                () -> new UserCredentialsNotFoundException(request.login()));

        return buildTokenResponse(credentials);
    }

    @Override
    @Transactional(readOnly = true)
    public TokenResponse refresh (RefreshTokenRequest request){
        Claims claims;
        try {
            claims = jwtService.parseToken(request.refreshToken());
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidTokenException("Invalid refresh token");
        }
        if (!JwtService.REFRESH_TOKEN_TYPE.equals(jwtService.extractType(claims))) {
            throw new InvalidTokenException("Provided token is not a refresh token");
        }

        Long userId = jwtService.extractUserId(claims);
        UserCredentials credentials = repository.findById(userId).orElseThrow(
                () -> new UserCredentialsNotFoundException(userId));
        if(!credentials.isActive()){
            throw new DisabledException("User is deactivated");
        }
        return buildTokenResponse(credentials);
    }

    @Override
    @Transactional(readOnly = true)
    public ValidateTokenResponse validate (ValidateTokenRequest request){
        try {
            Claims claims = jwtService.parseToken(request.token());
            Long userId = jwtService.extractUserId(claims);
            String role = jwtService.extractRole(claims).name();

            boolean userActive = repository.findByUserId(userId)
                    .map(UserCredentials::isActive)
                    .orElse(false);
            if (!userActive) {
                return new ValidateTokenResponse(false, null, null, "User is not active");
            }
            return new ValidateTokenResponse(true, userId, role, null);
        } catch (JwtException | IllegalArgumentException e) {
            return new ValidateTokenResponse(false, null, null, "Invalid or expired token");
        }
    }

    @Override
    @Transactional(readOnly = true)
    public UserCredentialsResponse getCredentials (Long userId){
        return repository.findByUserId(userId)
                .map(mapper::toResponse)
                .orElseThrow(() -> new UserCredentialsNotFoundException(userId));
    }

    private TokenResponse buildTokenResponse(UserCredentials credentials) {
        String accessToken = jwtService.generateAccessToken(credentials.getUserId(), credentials.getRole());
        String refreshToken = jwtService.generateRefreshToken(credentials.getUserId(), credentials.getRole());
        return new TokenResponse(accessToken, refreshToken, "Bearer",
                jwtProperties.accessTokenTtl().toSeconds());
    }

}
