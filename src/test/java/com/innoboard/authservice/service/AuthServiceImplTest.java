package com.innoboard.authservice.service;

import com.innoboard.authservice.config.JwtProperties;
import com.innoboard.authservice.domain.Role;
import com.innoboard.authservice.domain.UserCredentials;
import com.innoboard.authservice.dto.RegisterCredentialsRequest;
import com.innoboard.authservice.dto.TokenResponse;
import com.innoboard.authservice.dto.UserCredentialsResponse;
import com.innoboard.authservice.dto.ValidateTokenResponse;
import com.innoboard.authservice.exception.DuplicateCredentialsException;
import com.innoboard.authservice.exception.InvalidTokenException;
import com.innoboard.authservice.exception.UserCredentialsNotFoundException;
import com.innoboard.authservice.mapper.UserCredentialsMapper;
import com.innoboard.authservice.repository.UserCredentialsRepository;
import com.innoboard.authservice.security.JwtService;
import com.innoboard.authservice.service.impl.AuthServiceImpl;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    private static final Long USER_ID = 1L;
    private static final String LOGIN = "ivan";
    private static final String PASSWORD = "password123";

    @Mock
    private UserCredentialsRepository repository;
    @Mock
    private UserCredentialsMapper mapper;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtService jwtService;
    @Mock
    private JwtProperties jwtProperties;

    @InjectMocks
    private AuthServiceImpl authService;

    private RegisterCredentialsRequest registerRequest() {
        return new RegisterCredentialsRequest(USER_ID, LOGIN, PASSWORD);
    }

    private UserCredentials credentials(boolean active) {
        UserCredentials credentials = new UserCredentials();
        credentials.setUserId(USER_ID);
        credentials.setLogin(LOGIN);
        credentials.setPasswordHash("hash");
        credentials.setRole(Role.USER);
        credentials.setActive(active);
        return credentials;
    }

    private UserCredentialsResponse response() {
        return new UserCredentialsResponse(10L, USER_ID, LOGIN, "USER", Instant.now());
    }

    @Nested
    @DisplayName("register")
    class Register {

        @Test
        @DisplayName("assigns USER role server-side and stores password hash")
        void assignsServerSideRoleAndHashedPassword() {
            when(repository.existsByLogin(LOGIN)).thenReturn(false);
            when(repository.existsByUserId(USER_ID)).thenReturn(false);
            when(passwordEncoder.encode(PASSWORD)).thenReturn("hash");
            when(repository.save(any(UserCredentials.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            UserCredentialsResponse expected = response();
            when(mapper.toResponse(any(UserCredentials.class))).thenReturn(expected);

            UserCredentialsResponse result = authService.register(registerRequest());

            assertThat(result).isSameAs(expected);

            ArgumentCaptor<UserCredentials> captor = ArgumentCaptor.forClass(UserCredentials.class);
            verify(repository).save(captor.capture());
            UserCredentials saved = captor.getValue();
            assertThat(saved.getUserId()).isEqualTo(USER_ID);
            assertThat(saved.getLogin()).isEqualTo(LOGIN);
            assertThat(saved.getPasswordHash()).isEqualTo("hash");
            assertThat(saved.getRole()).isEqualTo(Role.USER);
            assertThat(saved.isActive()).isTrue();
        }

        @Test
        @DisplayName("taken login yields 409, nothing saved")
        void duplicateLoginRejected() {
            when(repository.existsByLogin(LOGIN)).thenReturn(true);

            assertThatThrownBy(() -> authService.register(registerRequest()))
                    .isInstanceOf(DuplicateCredentialsException.class);
            verify(repository, never()).save(any());
        }

        @Test
        @DisplayName("userId with existing credentials yields 409, nothing saved")
        void duplicateUserIdRejected() {
            when(repository.existsByLogin(LOGIN)).thenReturn(false);
            when(repository.existsByUserId(USER_ID)).thenReturn(true);

            assertThatThrownBy(() -> authService.register(registerRequest()))
                    .isInstanceOf(DuplicateCredentialsException.class);
            verify(repository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("login")
    class Login {

        @Test
        @DisplayName("successful login returns token pair")
        void returnsTokenPair() {
            when(authenticationManager.authenticate(any())).thenReturn(
                    UsernamePasswordAuthenticationToken.unauthenticated(LOGIN, "hash"));
            when(repository.findByLogin(LOGIN)).thenReturn(Optional.of(credentials(true)));
            when(jwtService.generateAccessToken(USER_ID, Role.USER)).thenReturn("access-token");
            when(jwtService.generateRefreshToken(USER_ID, Role.USER)).thenReturn("refresh-token");
            when(jwtProperties.accessTokenTtl()).thenReturn(Duration.ofSeconds(900));

            TokenResponse result = authService.login(
                    new com.innoboard.authservice.dto.LoginRequest(LOGIN, PASSWORD));

            assertThat(result.accessToken()).isEqualTo("access-token");
            assertThat(result.refreshToken()).isEqualTo("refresh-token");
            assertThat(result.tokenType()).isEqualTo("Bearer");
            assertThat(result.expiresIn()).isEqualTo(900);
        }

        @Test
        @DisplayName("wrong password throws BadCredentialsException (401)")
        void badCredentialsRejected() {
            when(authenticationManager.authenticate(any()))
                    .thenThrow(new BadCredentialsException("Bad credentials"));

            assertThatThrownBy(() -> authService.login(
                            new com.innoboard.authservice.dto.LoginRequest(LOGIN, PASSWORD)))
                    .isInstanceOf(BadCredentialsException.class);
            verify(repository, never()).findByLogin(any());
        }

        @Test
        @DisplayName("unknown login throws UserCredentialsNotFoundException")
        void unknownLoginRejected() {
            when(authenticationManager.authenticate(any())).thenReturn(null);
            when(repository.findByLogin(LOGIN)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.login(
                            new com.innoboard.authservice.dto.LoginRequest(LOGIN, PASSWORD)))
                    .isInstanceOf(UserCredentialsNotFoundException.class);
        }
    }

    @Nested
    @DisplayName("refresh")
    class Refresh {

        private final Claims claims = mock(Claims.class);
        private final String refreshToken = "refresh.token.value";

        @Test
        @DisplayName("malformed token throws InvalidTokenException (401)")
        void malformedTokenRejected() {
            when(jwtService.parseToken(refreshToken)).thenThrow(new JwtException("broken"));

            assertThatThrownBy(() -> authService.refresh(
                            new com.innoboard.authservice.dto.RefreshTokenRequest(refreshToken)))
                    .isInstanceOf(InvalidTokenException.class);
        }

        @Test
        @DisplayName("access token instead of refresh throws InvalidTokenException")
        void accessTokenTypeRejected() {
            when(jwtService.parseToken(refreshToken)).thenReturn(claims);
            when(jwtService.extractType(claims)).thenReturn(JwtService.ACCESS_TOKEN_TYPE);

            assertThatThrownBy(() -> authService.refresh(
                            new com.innoboard.authservice.dto.RefreshTokenRequest(refreshToken)))
                    .isInstanceOf(InvalidTokenException.class);
            verify(repository, never()).findByUserId(any());
        }

        @Test
        @DisplayName("no credentials for userId throws UserCredentialsNotFoundException")
        void unknownUserRejected() {
            when(jwtService.parseToken(refreshToken)).thenReturn(claims);
            when(jwtService.extractType(claims)).thenReturn(JwtService.REFRESH_TOKEN_TYPE);
            when(jwtService.extractUserId(claims)).thenReturn(USER_ID);
            when(repository.findByUserId(USER_ID)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.refresh(
                            new com.innoboard.authservice.dto.RefreshTokenRequest(refreshToken)))
                    .isInstanceOf(UserCredentialsNotFoundException.class);
        }

        @Test
        @DisplayName("inactive user throws DisabledException")
        void inactiveUserRejected() {
            when(jwtService.parseToken(refreshToken)).thenReturn(claims);
            when(jwtService.extractType(claims)).thenReturn(JwtService.REFRESH_TOKEN_TYPE);
            when(jwtService.extractUserId(claims)).thenReturn(USER_ID);
            when(repository.findByUserId(USER_ID)).thenReturn(Optional.of(credentials(false)));

            assertThatThrownBy(() -> authService.refresh(
                            new com.innoboard.authservice.dto.RefreshTokenRequest(refreshToken)))
                    .isInstanceOf(DisabledException.class);
        }

        @Test
        @DisplayName("successful refresh returns new token pair")
        void returnsNewTokenPair() {
            when(jwtService.parseToken(refreshToken)).thenReturn(claims);
            when(jwtService.extractType(claims)).thenReturn(JwtService.REFRESH_TOKEN_TYPE);
            when(jwtService.extractUserId(claims)).thenReturn(USER_ID);
            when(repository.findByUserId(USER_ID)).thenReturn(Optional.of(credentials(true)));
            when(jwtService.generateAccessToken(USER_ID, Role.USER)).thenReturn("new-access");
            when(jwtService.generateRefreshToken(USER_ID, Role.USER)).thenReturn("new-refresh");
            when(jwtProperties.accessTokenTtl()).thenReturn(Duration.ofSeconds(900));

            TokenResponse result = authService.refresh(
                    new com.innoboard.authservice.dto.RefreshTokenRequest(refreshToken));

            assertThat(result.accessToken()).isEqualTo("new-access");
            assertThat(result.refreshToken()).isEqualTo("new-refresh");
        }
    }

    @Nested
    @DisplayName("validate")
    class Validate {

        private final Claims claims = mock(Claims.class);

        @Test
        @DisplayName("valid token for active user")
        void validTokenForActiveUser() {
            when(jwtService.parseToken("token")).thenReturn(claims);
            when(jwtService.extractUserId(claims)).thenReturn(USER_ID);
            when(jwtService.extractRole(claims)).thenReturn(Role.USER);
            when(repository.findByUserId(USER_ID)).thenReturn(Optional.of(credentials(true)));

            ValidateTokenResponse result = authService.validate(
                    new com.innoboard.authservice.dto.ValidateTokenRequest("token"));

            assertThat(result.valid()).isTrue();
            assertThat(result.userId()).isEqualTo(USER_ID);
            assertThat(result.role()).isEqualTo("USER");
            assertThat(result.reason()).isNull();
        }

        @Test
        @DisplayName("token valid but user inactive")
        void inactiveUserInvalid() {
            when(jwtService.parseToken("token")).thenReturn(claims);
            when(jwtService.extractUserId(claims)).thenReturn(USER_ID);
            when(jwtService.extractRole(claims)).thenReturn(Role.USER);
            when(repository.findByUserId(USER_ID)).thenReturn(Optional.of(credentials(false)));

            ValidateTokenResponse result = authService.validate(
                    new com.innoboard.authservice.dto.ValidateTokenRequest("token"));

            assertThat(result.valid()).isFalse();
            assertThat(result.reason()).isEqualTo("User is not active");
        }

        @Test
        @DisplayName("unknown userId in token is invalid")
        void unknownUserInvalid() {
            when(jwtService.parseToken("token")).thenReturn(claims);
            when(jwtService.extractUserId(claims)).thenReturn(USER_ID);
            when(jwtService.extractRole(claims)).thenReturn(Role.USER);
            when(repository.findByUserId(USER_ID)).thenReturn(Optional.empty());

            ValidateTokenResponse result = authService.validate(
                    new com.innoboard.authservice.dto.ValidateTokenRequest("token"));

            assertThat(result.valid()).isFalse();
        }

        @Test
        @DisplayName("broken token is invalid without exception")
        void brokenTokenInvalid() {
            when(jwtService.parseToken("token")).thenThrow(new JwtException("broken"));

            ValidateTokenResponse result = authService.validate(
                    new com.innoboard.authservice.dto.ValidateTokenRequest("token"));

            assertThat(result.valid()).isFalse();
            assertThat(result.reason()).isEqualTo("Invalid or expired token");
        }
    }

    @Nested
    @DisplayName("getCredentials")
    class GetCredentials {

        @Test
        @DisplayName("existing credentials are mapped to response")
        void returnsMappedResponse() {
            when(repository.findByUserId(USER_ID)).thenReturn(Optional.of(credentials(true)));
            UserCredentialsResponse expected = response();
            when(mapper.toResponse(any(UserCredentials.class))).thenReturn(expected);

            UserCredentialsResponse result = authService.getCredentials(USER_ID);

            assertThat(result).isSameAs(expected);
        }

        @Test
        @DisplayName("missing credentials throw UserCredentialsNotFoundException")
        void missingCredentialsRejected() {
            when(repository.findByUserId(USER_ID)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.getCredentials(USER_ID))
                    .isInstanceOf(UserCredentialsNotFoundException.class);
        }
    }
}
