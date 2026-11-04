package com.innoboard.authservice.security;

import com.innoboard.authservice.config.JwtProperties;
import com.innoboard.authservice.domain.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.WeakKeyException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("JwtService: token generation and parsing")
class JwtServiceTest {

    private static final String SECRET = "test-secret-key-for-auth-service-min-32-bytes!!";
    private static final Long USER_ID = 1L;

    private final JwtService jwtService = new JwtService(
            new JwtProperties(SECRET, Duration.ofSeconds(900), Duration.ofSeconds(604800)));

    @Test
    @DisplayName("access token survives round-trip: subject, role, type")
    void accessTokenRoundTrip() {
        String token = jwtService.generateAccessToken(USER_ID, Role.USER);

        Claims claims = jwtService.parseToken(token);

        assertThat(jwtService.extractUserId(claims)).isEqualTo(USER_ID);
        assertThat(jwtService.extractRole(claims)).isEqualTo(Role.USER);
        assertThat(jwtService.extractType(claims)).isEqualTo(JwtService.ACCESS_TOKEN_TYPE);
    }

    @Test
    @DisplayName("refresh token carries type=refresh")
    void refreshTokenHasRefreshType() {
        String token = jwtService.generateRefreshToken(USER_ID, Role.USER);

        Claims claims = jwtService.parseToken(token);

        assertThat(jwtService.extractType(claims)).isEqualTo(JwtService.REFRESH_TOKEN_TYPE);
    }

    @Test
    @DisplayName("expired token is rejected")
    void expiredTokenRejected() {
        JwtService expiredService = new JwtService(
                new JwtProperties(SECRET, Duration.ofSeconds(-60), Duration.ofSeconds(-60)));

        String token = expiredService.generateAccessToken(USER_ID, Role.USER);

        assertThatThrownBy(() -> jwtService.parseToken(token))
                .isInstanceOf(ExpiredJwtException.class);
    }

    @Test
    @DisplayName("token signed with a different key is rejected")
    void foreignSignatureRejected() {
        JwtService otherService = new JwtService(
                new JwtProperties("another-secret-key-for-auth-service-32-bytes!!",
                        Duration.ofSeconds(900), Duration.ofSeconds(604800)));

        String token = otherService.generateAccessToken(USER_ID, Role.USER);

        assertThatThrownBy(() -> jwtService.parseToken(token))
                .isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("garbage string causes JwtException")
    void garbageStringRejected() {
        assertThatThrownBy(() -> jwtService.parseToken("not-a-jwt"))
                .isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("secret shorter than 32 bytes is rejected at construction")
    void shortSecretRejected() {
        assertThatThrownBy(() -> new JwtService(
                new JwtProperties("short", Duration.ofSeconds(900), Duration.ofSeconds(604800))))
                .isInstanceOf(WeakKeyException.class);
    }
}
