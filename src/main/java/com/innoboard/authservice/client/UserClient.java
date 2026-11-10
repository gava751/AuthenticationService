package com.innoboard.authservice.client;

import com.innoboard.authservice.dto.CreateUserRequest;
import com.innoboard.authservice.exception.DuplicateCredentialsException;
import com.innoboard.authservice.exception.UserCreationException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

@Component
@RequiredArgsConstructor
public class UserClient {

    private final RestClient userRestClient;

    public Long createUser(CreateUserRequest request) {
        try {
            UserResponse response = userRestClient.post()
                    .uri("/internal/users")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .body(UserResponse.class);
            if (response == null || response.id() == null) {
                throw new UserCreationException("User Service returned no user id");
            }
            return response.id();
        } catch (RestClientResponseException e) {
            if (e.getStatusCode() == HttpStatus.CONFLICT) {
                throw new DuplicateCredentialsException("Email already registered");
            }
            throw new UserCreationException("User Service rejected the request: " + e.getStatusCode());
        } catch (RestClientException e) {
            throw new UserCreationException("User Service is unavailable");
        }
    }

    public void deleteUser(Long userId) {
        userRestClient.delete()
                .uri("/internal/users/{id}", userId)
                .retrieve()
                .toBodilessEntity();
    }
}
