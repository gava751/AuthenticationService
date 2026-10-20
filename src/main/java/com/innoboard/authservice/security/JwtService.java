package com.innoboard.authservice.security;

import com.innoboard.authservice.config.JwtProperties;
import com.innoboard.authservice.domain.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Component
public class JwtService {

    public static final String TYPE_CLAIM = "type";
    public static final String ROLE_CLAIM = "role";
    public static final String ACCESS_TOKEN_TYPE = "access";
    public static final String REFRESH_TOKEN_TYPE = "refresh";

    private final JwtProperties properties;
    private final SecretKey secretKey;

    public JwtService(JwtProperties properties) {
        this.properties = properties;
        this.secretKey= Keys.hmacShaKeyFor(properties.secret().getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(Long userId, Role role) {
        return buildToken(userId, role, ACCESS_TOKEN_TYPE, properties.accessTokenTtl());
    }

    public String generateRefreshToken(Long userId, Role role) {
        return buildToken(userId, role, REFRESH_TOKEN_TYPE, properties.refreshTokenTtl());
    }

    public Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Long extractUserId(Claims claims) {
        return Long.valueOf(claims.getSubject());
    }

    public Role extractRole(Claims claims) {
        return Role.valueOf(claims.get(ROLE_CLAIM,String.class));
    }

    public String extractType(Claims claims) {
        return claims.get(TYPE_CLAIM,String.class);
    }

    private String buildToken(Long userId, Role role, String type, Duration ttl) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(String.valueOf(userId))
                .claim(ROLE_CLAIM, role.name())
                .claim(TYPE_CLAIM, type)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(ttl)))
                .signWith(secretKey)
                .compact();
    }

}
