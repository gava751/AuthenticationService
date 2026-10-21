package com.innoboard.authservice.controller;

import com.innoboard.authservice.domain.UserCredentials;
import com.innoboard.authservice.dto.*;
import com.innoboard.authservice.repository.UserCredentialsRepository;
import com.innoboard.authservice.security.AuthUser;
import com.innoboard.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<UserCredentialsResponse> register(@Valid @RequestBody RegisterCredentialsRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/validate")
    public ResponseEntity<ValidateTokenResponse> validate(@Valid @RequestBody ValidateTokenRequest request) {
        return ResponseEntity.ok(authService.validate(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    @GetMapping("/credentials/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserCredentialsResponse> getCredentials(@PathVariable Long userId) {
        return ResponseEntity.ok(authService.getCredentials(userId));
    }

    @GetMapping("/me")
    public ResponseEntity<CurrentUserResponse> me(@AuthenticationPrincipal AuthUser currentUser) {
        return ResponseEntity.ok(new CurrentUserResponse(currentUser.userId(), currentUser.role().name()));
    }
}
