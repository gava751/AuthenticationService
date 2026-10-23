package com.innoboard.authservice.security;

import com.innoboard.authservice.domain.Role;

public record AuthUser(Long userId, Role role) {
}
