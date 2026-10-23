package com.innoboard.authservice.dto;

import jakarta.validation.constraints.NotBlank;

public record ValidateTokenRequest (
        @NotBlank(message = "Token must not be blank") String token
){}
