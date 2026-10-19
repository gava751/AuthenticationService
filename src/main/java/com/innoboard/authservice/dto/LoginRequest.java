package com.innoboard.authservice.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest (
        @NotBlank(message = "Login must not be blank") String login,
        @NotBlank(message = "Password must not be blank") String password
){}
