package com.innoboard.authservice.service;

import com.innoboard.authservice.dto.*;

public interface AuthService {

    UserCredentialsResponse register(RegisterCredentialsRequest request);

    TokenResponse login(LoginRequest request);

    TokenResponse refresh(RefreshTokenRequest request);

    ValidateTokenResponse validate(ValidateTokenRequest request);

    UserCredentialsResponse getCredentials(Long userId);
}
