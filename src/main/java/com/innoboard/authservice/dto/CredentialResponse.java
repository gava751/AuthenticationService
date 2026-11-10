package com.innoboard.authservice.dto;

import java.time.Instant;

public record CredentialResponse(
        Long id,
        Long userId,
        String username,
        String role,
        Instant createdAt
) {
}
