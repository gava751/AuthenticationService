package com.innoboard.authservice.client;

import com.innoboard.authservice.dto.CreateUserRequest;
import com.innoboard.authservice.exception.DuplicateCredentialsException;
import com.innoboard.authservice.exception.UserCreationException;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.net.ServerSocket;
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("UserClient over real HTTP")
class UserClientHttpTest {

    private static final MockWebServer userApi = new MockWebServer();
    private static final CreateUserRequest CREATE_REQUEST = new CreateUserRequest(
            "Ivan", "Ivanov", LocalDate.of(1990, 1, 1), "ivan@example.com");

    private static UserClient client;

    @BeforeAll
    static void startServer() throws IOException {
        userApi.start();
        client = new UserClient(RestClient.builder()
                .baseUrl(userApi.url("/").toString())
                .build());
    }

    @AfterAll
    static void stopServer() throws IOException {
        userApi.shutdown();
    }

    @Test
    @DisplayName("201 with user id is mapped to the returned id")
    void createdUserReturnsId() throws Exception {
        userApi.enqueue(new MockResponse()
                .setResponseCode(201)
                .setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .setBody("{\"id\":5}"));

        Long userId = client.createUser(CREATE_REQUEST);

        assertThat(userId).isEqualTo(5L);
        RecordedRequest request = userApi.takeRequest();
        assertThat(request.getMethod()).isEqualTo("POST");
        assertThat(request.getPath()).isEqualTo("/api/users");
        assertThat(request.getHeader("Content-Type")).startsWith(MediaType.APPLICATION_JSON_VALUE);
    }

    @Test
    @DisplayName("409 from User Service becomes DuplicateCredentialsException")
    void conflictBecomesDuplicateCredentials() {
        userApi.enqueue(new MockResponse()
                .setResponseCode(409)
                .setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .setBody("{}"));

        assertThatThrownBy(() -> client.createUser(CREATE_REQUEST))
                .isInstanceOf(DuplicateCredentialsException.class);
    }

    @Test
    @DisplayName("500 from User Service becomes UserCreationException")
    void serverErrorBecomesUserCreationException() {
        userApi.enqueue(new MockResponse()
                .setResponseCode(500)
                .setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .setBody("{}"));

        assertThatThrownBy(() -> client.createUser(CREATE_REQUEST))
                .isInstanceOf(UserCreationException.class);
    }

    @Test
    @DisplayName("connection failure becomes UserCreationException")
    void connectionFailureBecomesUserCreationException() throws IOException {
        int deadPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            deadPort = socket.getLocalPort();
        }
        UserClient unreachable = new UserClient(RestClient.builder()
                .baseUrl("http://localhost:" + deadPort)
                .build());

        assertThatThrownBy(() -> unreachable.createUser(CREATE_REQUEST))
                .isInstanceOf(UserCreationException.class);
    }

    @Test
    @DisplayName("compensation sends DELETE /api/users/{id}")
    void deleteUserSendsDeleteRequest() throws Exception {
        userApi.enqueue(new MockResponse().setResponseCode(204));

        client.deleteUser(7L);

        RecordedRequest request = userApi.takeRequest();
        assertThat(request.getMethod()).isEqualTo("DELETE");
        assertThat(request.getPath()).isEqualTo("/api/users/7");
    }
}
