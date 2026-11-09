package com.innoboard.authservice.integration;

import com.innoboard.authservice.client.UserClient;
import com.innoboard.authservice.dto.CreateUserRequest;
import com.innoboard.authservice.dto.LoginRequest;
import com.innoboard.authservice.dto.RegisterCredentialsRequest;
import com.innoboard.authservice.dto.RegisterCredentialsRequest;
import com.innoboard.authservice.repository.CredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;

import java.time.LocalDate;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public abstract class IntegrationTestBase {

    @ServiceConnection
    static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:18-alpine");

    static {
        postgres.start();
    }

    protected static final Long USER_ID = 1L;
    protected static final String LOGIN = "ivan";
    protected static final String PASSWORD = "password123";
    protected static final String NAME = "Ivan";
    protected static final String SURNAME = "Ivanov";
    protected static final LocalDate BIRTH_DATE = LocalDate.of(1990, 1, 1);
    protected static final String EMAIL = "ivan@example.com";

    @Autowired
    protected MockMvc mockMvc;
    @Autowired
    protected ObjectMapper objectMapper;
    @Autowired
    protected CredentialRepository credentialsRepository;
    @MockitoBean
    protected UserClient userClient;

    @BeforeEach
    void cleanState() {
        credentialsRepository.deleteAll();
        lenient().when(userClient.createUser(any(CreateUserRequest.class))).thenReturn(USER_ID);
    }

    protected String registerJson(String login, String password) throws Exception {
        return objectMapper.writeValueAsString(
                new RegisterCredentialsRequest(login, password, NAME, SURNAME, BIRTH_DATE, EMAIL));
    }

    protected String registerJson(RegisterCredentialsRequest request) throws Exception {
        return objectMapper.writeValueAsString(request);
    }

    protected void register(String login, String password) throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(login, password)))
                .andExpect(status().isCreated());
    }

    protected record Tokens(String accessToken, String refreshToken) {
    }

    protected Tokens login(String login, String password) throws Exception {
        String body = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(login, password))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readValue(body, Tokens.class);
    }
}
