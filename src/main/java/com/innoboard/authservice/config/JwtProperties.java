package com.innoboard.authservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import java.time.Duration;

@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(
        Resource privateKey,
        Resource publicKey,
        String keyId,
        Duration accessTokenTtl,
        Duration refreshTokenTtl
) {
}
