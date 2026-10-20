package com.innoboard.authservice.exception;

public class UserCredentialsNotFoundException extends RuntimeException {

    public UserCredentialsNotFoundException(Long userId) {
        super("User credentials not found for id " + userId);
    }

    public UserCredentialsNotFoundException(String message) {
        super(message);
    }
}
