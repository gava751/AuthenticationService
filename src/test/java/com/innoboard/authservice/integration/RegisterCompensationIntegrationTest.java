package com.innoboard.authservice.integration;

import com.innoboard.authservice.client.UserClient;
import com.innoboard.authservice.domain.Credential;
import com.innoboard.authservice.dto.RegisterCredentialsRequest;
import com.innoboard.authservice.repository.CredentialRepository;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.LocalDate;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DisplayName("register compensates a failed local save with HTTP DELETE")
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RegisterCompensationIntegrationTest {

    static final MockWebServer userApi = new MockWebServer();

    @ServiceConnection
    static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:18-alpine");

    static {
        postgres.start();
        try {
            userApi.start();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @MockitoBean
    private CredentialRepository credentialRepository;

    @TestConfiguration(proxyBeanMethods = false)
    static class HttpUserClientConfig {

        @Bean
        @Primary
        UserClient httpUserClient() {
            return new UserClient(RestClient.builder()
                    .baseUrl(userApi.url("/").toString())
                    .build());
        }
    }

    @Test
    void failedLocalSaveCompensatesWithHttpDelete() throws Exception {
        when(credentialRepository.existsByUsername(any(String.class))).thenReturn(false);
        when(credentialRepository.save(any(Credential.class)))
                .thenThrow(new IllegalStateException("save failed"));
        userApi.enqueue(new MockResponse()
                .setResponseCode(201)
                .setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .setBody("{\"id\":1}"));
        userApi.enqueue(new MockResponse().setResponseCode(204));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterCredentialsRequest(
                                "ivan", "password123", "Ivan", "Ivanov",
                                LocalDate.of(1990, 1, 1), "ivan@example.com"))))
                .andExpect(status().isInternalServerError());

        RecordedRequest created = userApi.takeRequest(1, TimeUnit.SECONDS);
        assertThat(created).isNotNull();
        assertThat(created.getMethod()).isEqualTo("POST");
        assertThat(created.getPath()).isEqualTo("/internal/users");
        RecordedRequest deleted = userApi.takeRequest(1, TimeUnit.SECONDS);
        assertThat(deleted).isNotNull();
        assertThat(deleted.getMethod()).isEqualTo("DELETE");
        assertThat(deleted.getPath()).isEqualTo("/internal/users/1");
    }
}
