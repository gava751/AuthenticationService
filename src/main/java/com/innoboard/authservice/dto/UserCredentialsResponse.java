package com.innoboard.authservice.dto;

import java.time.Instant;

public record UserCredentialsResponse (
        Long id,
        Long userId,
        String login,
        String role,
        Instant createdAt
){}
