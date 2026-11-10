package com.innoboard.authservice.exception;

public class AuthCredentialsNotFoundException extends RuntimeException {

    public AuthCredentialsNotFoundException(Long userId) {
        super("Credentials not found for user %d".formatted(userId));
    }
}
