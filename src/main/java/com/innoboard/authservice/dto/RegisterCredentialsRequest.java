package com.innoboard.authservice.dto;

import com.innoboard.authservice.validation.PasswordByteLength;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

public record RegisterCredentialsRequest(
        @NotBlank(message = "Login must not be blank")
        @Size(min = 3, max = 50, message = "Login must be between 3 and 50 characters")
        String login,
        @NotBlank(message = "Password must not be blank")
        @Size(min = 8, max = 72, message = "Password must be between 8 and 72 characters")
        @PasswordByteLength(message = "Password must be at most 72 bytes")
        String password,
        @NotBlank(message = "Name must not be blank")
        String name,
        @NotBlank(message = "Surname must not be blank")
        String surname,
        @NotNull(message = "Birth date is required")
        @Past(message = "Birth date must be in the past")
        LocalDate birthDate,
        @NotBlank(message = "Email must not be blank")
        @Email(message = "Email must be valid")
        String email
) {
}
