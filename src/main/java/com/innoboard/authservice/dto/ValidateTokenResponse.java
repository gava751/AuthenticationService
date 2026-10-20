package com.innoboard.authservice.dto;

public record ValidateTokenResponse (

        boolean valid,
        Long userId,
        String role,
        String reason
){}
