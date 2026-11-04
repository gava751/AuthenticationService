package com.innoboard.authservice.integration;

import com.innoboard.authservice.dto.RegisterCredentialsRequest;
import com.innoboard.authservice.repository.UserCredentialsRepository;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;

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

    @Autowired
    protected MockMvc mockMvc;
    @Autowired
    protected ObjectMapper objectMapper;
    @Autowired
    protected UserCredentialsRepository credentialsRepository;

    @BeforeEach
    void cleanState() {
        credentialsRepository.deleteAll();
    }

    protected String registerJson(Long userId, String login, String password) throws Exception {
        return objectMapper.writeValueAsString(new RegisterCredentialsRequest(userId, login, password));
    }

    protected void register(Long userId, String login, String password) throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(userId, login, password)))
                .andExpect(status().isCreated());
    }

    protected record Tokens(String accessToken, String refreshToken) {}

    protected Tokens login(String login, String password) throws Exception {
        String body = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new com.innoboard.authservice.dto.LoginRequest(login, password))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readValue(body, Tokens.class);
    }
}
