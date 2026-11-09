package com.innoboard.authservice.service;

import com.innoboard.authservice.client.UserClient;
import com.innoboard.authservice.config.JwtProperties;
import com.innoboard.authservice.domain.Credential;
import com.innoboard.authservice.domain.Role;
import com.innoboard.authservice.dto.CreateUserRequest;
import com.innoboard.authservice.dto.CredentialResponse;
import com.innoboard.authservice.dto.LoginRequest;
import com.innoboard.authservice.dto.RefreshTokenRequest;
import com.innoboard.authservice.dto.RegisterCredentialsRequest;
import com.innoboard.authservice.dto.TokenResponse;
import com.innoboard.authservice.exception.AuthCredentialsNotFoundException;
import com.innoboard.authservice.exception.DuplicateCredentialsException;
import com.innoboard.authservice.exception.InvalidTokenException;
import com.innoboard.authservice.exception.UserCreationException;
import com.innoboard.authservice.mapper.CredentialMapper;
import com.innoboard.authservice.repository.CredentialRepository;
import com.innoboard.authservice.security.AuthUser;
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
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    private static final Long USER_ID = 1L;
    private static final String LOGIN = "ivan";
    private static final String PASSWORD = "password123";
    private static final String NAME = "Ivan";
    private static final String SURNAME = "Ivanov";
    private static final LocalDate BIRTH_DATE = LocalDate.of(1990, 1, 1);
    private static final String EMAIL = "ivan@example.com";

    @Mock
    private CredentialRepository repository;
    @Mock
    private CredentialMapper mapper;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtService jwtService;
    @Mock
    private JwtProperties jwtProperties;
    @Mock
    private UserClient userClient;
    @Mock
    private TransactionTemplate transactionTemplate;

    @InjectMocks
    private AuthServiceImpl authService;

    private RegisterCredentialsRequest registerRequest() {
        return new RegisterCredentialsRequest(LOGIN, PASSWORD, NAME, SURNAME, BIRTH_DATE, EMAIL);
    }

    private Credential credentials(boolean active) {
        Credential credentials = new Credential();
        credentials.setUserId(USER_ID);
        credentials.setUsername(LOGIN);
        credentials.setPasswordHash("hash");
        credentials.setRole(Role.USER);
        credentials.setActive(active);
        return credentials;
    }

    private CredentialResponse response() {
        return new CredentialResponse(10L, USER_ID, LOGIN, "USER", Instant.now());
    }

    private void runCallbackInTransaction() {
        when(transactionTemplate.execute(any())).thenAnswer(invocation ->
                ((TransactionCallback<CredentialResponse>) invocation.getArgument(0)).doInTransaction(null));
    }

    @Nested
    @DisplayName("register")
    class Register {

        @Test
        @DisplayName("creates user in User Service and saves credentials with the returned user_id")
        void createsUserThroughUserServiceAndSavesCredentials() {
            when(repository.existsByUsername(LOGIN)).thenReturn(false);
            when(userClient.createUser(any(CreateUserRequest.class))).thenReturn(USER_ID);
            when(mapper.toEntity(any(RegisterCredentialsRequest.class))).thenReturn(new Credential());
            when(passwordEncoder.encode(PASSWORD)).thenReturn("hash");
            when(repository.save(any(Credential.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            CredentialResponse expected = response();
            when(mapper.toResponse(any(Credential.class))).thenReturn(expected);
            runCallbackInTransaction();

            CredentialResponse result = authService.register(registerRequest());

            assertThat(result).isSameAs(expected);
            verify(userClient).createUser(any(CreateUserRequest.class));

            ArgumentCaptor<Credential> captor = ArgumentCaptor.forClass(Credential.class);
            verify(repository).save(captor.capture());
            Credential saved = captor.getValue();
            assertThat(saved.getUserId()).isEqualTo(USER_ID);
            assertThat(saved.getPasswordHash()).isEqualTo("hash");
            assertThat(saved.getRole()).isEqualTo(Role.USER);
            assertThat(saved.isActive()).isTrue();
        }

        @Test
        @DisplayName("taken login yields 409, User Service is not called")
        void duplicateLoginRejected() {
            when(repository.existsByUsername(LOGIN)).thenReturn(true);

            assertThatThrownBy(() -> authService.register(registerRequest()))
                    .isInstanceOf(DuplicateCredentialsException.class);
            verify(userClient, never()).createUser(any());
            verify(repository, never()).save(any());
        }

        @Test
        @DisplayName("duplicate email in User Service yields 409, nothing saved")
        void userServiceConflictRejected() {
            when(repository.existsByUsername(LOGIN)).thenReturn(false);
            when(userClient.createUser(any(CreateUserRequest.class)))
                    .thenThrow(new DuplicateCredentialsException("Email already registered"));

            assertThatThrownBy(() -> authService.register(registerRequest()))
                    .isInstanceOf(DuplicateCredentialsException.class);
            verify(repository, never()).save(any());
        }

        @Test
        @DisplayName("unavailable User Service yields UserCreationException, nothing saved")
        void userServiceUnavailableRejected() {
            when(repository.existsByUsername(LOGIN)).thenReturn(false);
            when(userClient.createUser(any(CreateUserRequest.class)))
                    .thenThrow(new UserCreationException("User Service is unavailable"));

            assertThatThrownBy(() -> authService.register(registerRequest()))
                    .isInstanceOf(UserCreationException.class);
            verify(repository, never()).save(any());
        }

        @Test
        @DisplayName("local save failure compensates with DELETE of the created user")
        void localSaveFailureCompensates() {
            when(repository.existsByUsername(LOGIN)).thenReturn(false);
            when(userClient.createUser(any(CreateUserRequest.class))).thenReturn(USER_ID);
            when(transactionTemplate.execute(any()))
                    .thenThrow(new DataIntegrityViolationException("uq_credentials_username"));

            assertThatThrownBy(() -> authService.register(registerRequest()))
                    .isInstanceOf(DuplicateCredentialsException.class);
            verify(userClient).deleteUser(USER_ID);
        }

        @Test
        @DisplayName("integrity violation on another constraint is rethrown as-is after compensation")
        void otherConstraintViolationRethrowsAsIs() {
            when(repository.existsByUsername(LOGIN)).thenReturn(false);
            when(userClient.createUser(any(CreateUserRequest.class))).thenReturn(USER_ID);
            when(transactionTemplate.execute(any()))
                    .thenThrow(new DataIntegrityViolationException("uq_credentials_user_id"));

            assertThatThrownBy(() -> authService.register(registerRequest()))
                    .isInstanceOf(DataIntegrityViolationException.class)
                    .hasMessage("uq_credentials_user_id");
            verify(userClient).deleteUser(USER_ID);
        }

        @Test
        @DisplayName("any local failure rethrows after compensation, rollback error does not mask it")
        void arbitraryLocalFailureCompensatesAndRethrows() {
            when(repository.existsByUsername(LOGIN)).thenReturn(false);
            when(userClient.createUser(any(CreateUserRequest.class))).thenReturn(USER_ID);
            when(transactionTemplate.execute(any())).thenThrow(new IllegalStateException("pool exhausted"));
            doThrow(new UserCreationException("User Service is unavailable"))
                    .when(userClient).deleteUser(USER_ID);

            assertThatThrownBy(() -> authService.register(registerRequest()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("pool exhausted");
            verify(userClient).deleteUser(USER_ID);
        }
    }

    @Nested
    @DisplayName("login")
    class Login {

        @Test
        @DisplayName("successful login builds tokens from the authenticated principal")
        void returnsTokenPair() {
            AuthUser principal = AuthUser.fromToken(USER_ID, Role.USER);
            when(authenticationManager.authenticate(any())).thenReturn(
                    new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities()));
            when(jwtService.generateAccessToken(USER_ID, Role.USER)).thenReturn("access-token");
            when(jwtService.generateRefreshToken(USER_ID, Role.USER)).thenReturn("refresh-token");
            when(jwtProperties.accessTokenTtl()).thenReturn(Duration.ofSeconds(900));

            TokenResponse result = authService.login(new LoginRequest(LOGIN, PASSWORD));

            assertThat(result.accessToken()).isEqualTo("access-token");
            assertThat(result.refreshToken()).isEqualTo("refresh-token");
            assertThat(result.tokenType()).isEqualTo("Bearer");
            assertThat(result.expiresIn()).isEqualTo(900);
            verify(repository, never()).findByUsername(any());
        }

        @Test
        @DisplayName("wrong password throws BadCredentialsException (401)")
        void badCredentialsRejected() {
            when(authenticationManager.authenticate(any()))
                    .thenThrow(new BadCredentialsException("Bad credentials"));

            assertThatThrownBy(() -> authService.login(new LoginRequest(LOGIN, PASSWORD)))
                    .isInstanceOf(BadCredentialsException.class);
            verify(repository, never()).findByUsername(any());
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

            assertThatThrownBy(() -> authService.refresh(new RefreshTokenRequest(refreshToken)))
                    .isInstanceOf(InvalidTokenException.class);
        }

        @Test
        @DisplayName("access token instead of refresh throws InvalidTokenException")
        void accessTokenTypeRejected() {
            when(jwtService.parseToken(refreshToken)).thenReturn(claims);
            when(jwtService.extractType(claims)).thenReturn(JwtService.ACCESS_TOKEN_TYPE);

            assertThatThrownBy(() -> authService.refresh(new RefreshTokenRequest(refreshToken)))
                    .isInstanceOf(InvalidTokenException.class);
            verify(repository, never()).findByUserId(any());
        }

        @Test
        @DisplayName("no credentials for userId is indistinguishable from a broken token (401, same text)")
        void unknownUserRejected() {
            when(jwtService.parseToken(refreshToken)).thenReturn(claims);
            when(jwtService.extractType(claims)).thenReturn(JwtService.REFRESH_TOKEN_TYPE);
            when(jwtService.extractUserId(claims)).thenReturn(USER_ID);
            when(repository.findByUserId(USER_ID)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.refresh(new RefreshTokenRequest(refreshToken)))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessage("Invalid refresh token");
        }

        @Test
        @DisplayName("inactive user is indistinguishable from a broken token (401, same text)")
        void inactiveUserRejected() {
            when(jwtService.parseToken(refreshToken)).thenReturn(claims);
            when(jwtService.extractType(claims)).thenReturn(JwtService.REFRESH_TOKEN_TYPE);
            when(jwtService.extractUserId(claims)).thenReturn(USER_ID);
            when(repository.findByUserId(USER_ID)).thenReturn(Optional.of(credentials(false)));

            assertThatThrownBy(() -> authService.refresh(new RefreshTokenRequest(refreshToken)))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessage("Invalid refresh token");
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

            TokenResponse result = authService.refresh(new RefreshTokenRequest(refreshToken));

            assertThat(result.accessToken()).isEqualTo("new-access");
            assertThat(result.refreshToken()).isEqualTo("new-refresh");
        }
    }

    @Nested
    @DisplayName("getCredentials")
    class GetCredentials {

        @Test
        @DisplayName("existing credentials are mapped to response")
        void returnsMappedResponse() {
            when(repository.findByUserId(USER_ID)).thenReturn(Optional.of(credentials(true)));
            CredentialResponse expected = response();
            when(mapper.toResponse(any(Credential.class))).thenReturn(expected);

            CredentialResponse result = authService.getCredentials(USER_ID);

            assertThat(result).isSameAs(expected);
        }

        @Test
        @DisplayName("missing credentials throw CredentialNotFoundException")
        void missingCredentialsRejected() {
            when(repository.findByUserId(USER_ID)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.getCredentials(USER_ID))
                    .isInstanceOf(AuthCredentialsNotFoundException.class);
        }
    }

    @Nested
    @DisplayName("me")
    class Me {

        @Test
        @DisplayName("builds response from the authenticated principal")
        void buildsResponseFromPrincipal() {
            AuthUser user = AuthUser.fromToken(USER_ID, Role.USER);

            var result = authService.me(user);

            assertThat(result.userId()).isEqualTo(USER_ID);
            assertThat(result.role()).isEqualTo("USER");
        }
    }
}
