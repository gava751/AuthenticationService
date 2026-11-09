package com.innoboard.authservice.controller;

import com.innoboard.authservice.dto.CredentialResponse;
import com.innoboard.authservice.dto.CurrentUserResponse;
import com.innoboard.authservice.dto.LoginRequest;
import com.innoboard.authservice.dto.RefreshTokenRequest;
import com.innoboard.authservice.dto.RegisterCredentialsRequest;
import com.innoboard.authservice.dto.TokenResponse;
import com.innoboard.authservice.security.AuthUser;
import com.innoboard.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<CredentialResponse> register(@Valid @RequestBody RegisterCredentialsRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    @GetMapping("/credentials/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<CredentialResponse> getCredentials(@PathVariable Long userId) {
        return ResponseEntity.ok(authService.getCredentials(userId));
    }

    @GetMapping("/me")
    public ResponseEntity<CurrentUserResponse> me(@AuthenticationPrincipal AuthUser currentUser) {
        return ResponseEntity.ok(authService.me(currentUser));
    }
}
