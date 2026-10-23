package com.innoboard.authservice.dto;

import com.innoboard.authservice.domain.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record RegisterCredentialsRequest (
    @NotNull(message = "User id must not be null") Long userId,
    @NotBlank(message = "Login must not be blank")
    @Size(min = 3, max = 50, message = "Login must be between 3 and 50 characters")
    String login,
    @NotBlank(message = "Password must not be blank")
    @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters")
    String password,
    @NotNull(message = "Role must not be null") Role role
)
{}
