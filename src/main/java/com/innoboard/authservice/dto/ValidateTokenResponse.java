package com.innoboard.authservice.dto;

import java.lang.invoke.MethodHandles;

public record ValidateTokenResponse (

        boolean valid,
        Long userId,
        String role,
        String reason
){}
