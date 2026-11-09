package com.innoboard.authservice.service;

import com.innoboard.authservice.dto.CredentialResponse;
import com.innoboard.authservice.dto.CurrentUserResponse;
import com.innoboard.authservice.dto.LoginRequest;
import com.innoboard.authservice.dto.RefreshTokenRequest;
import com.innoboard.authservice.dto.RegisterCredentialsRequest;
import com.innoboard.authservice.dto.TokenResponse;
import com.innoboard.authservice.security.AuthUser;

public interface AuthService {

    CredentialResponse register(RegisterCredentialsRequest request);

    TokenResponse login(LoginRequest request);

    TokenResponse refresh(RefreshTokenRequest request);

    CredentialResponse getCredentials(Long userId);

    CurrentUserResponse me(AuthUser user);
}
