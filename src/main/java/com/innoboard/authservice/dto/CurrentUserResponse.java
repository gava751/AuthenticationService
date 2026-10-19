package com.innoboard.authservice.dto;

public record CurrentUserResponse (
        Long userId,
        String role
){}
