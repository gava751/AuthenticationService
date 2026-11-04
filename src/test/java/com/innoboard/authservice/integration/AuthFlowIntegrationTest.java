package com.innoboard.authservice.integration;

import com.innoboard.authservice.dto.LoginRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DisplayName("Integration flow: register -> login -> validate -> refresh -> me")
class AuthFlowIntegrationTest extends IntegrationTestBase {

    private static final Long USER_ID = 1L;
    private static final String LOGIN = "ivan";
    private static final String PASSWORD = "password123";

    @Test
    void registerReturnsCreatedCredentialsWithDefaultUserRole() throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(USER_ID, LOGIN, PASSWORD)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.userId").value(USER_ID))
                .andExpect(jsonPath("$.login").value(LOGIN))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.createdAt").isNotEmpty());
    }

    @Test
    void loginReturnsBothTokens() throws Exception {
        register(USER_ID, LOGIN, PASSWORD);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest(LOGIN, PASSWORD))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").isNumber());
    }

    @Test
    void validateAcceptsFreshAccessToken() throws Exception {
        register(USER_ID, LOGIN, PASSWORD);
        String accessToken = login(LOGIN, PASSWORD).accessToken();

        mockMvc.perform(post("/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + accessToken + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.userId").value(USER_ID))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.reason").isEmpty());
    }

    @Test
    void meReturnsAuthenticatedUser() throws Exception {
        register(USER_ID, LOGIN, PASSWORD);
        String accessToken = login(LOGIN, PASSWORD).accessToken();

        mockMvc.perform(get("/auth/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(USER_ID))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void refreshReturnsUsableNewTokens() throws Exception {
        register(USER_ID, LOGIN, PASSWORD);
        Tokens old = login(LOGIN, PASSWORD);

        String body = mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + old.refreshToken() + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        Tokens fresh = objectMapper.readValue(body, Tokens.class);

        mockMvc.perform(get("/auth/me").header("Authorization", "Bearer " + fresh.accessToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(USER_ID));
    }

    @Test
    @DisplayName("access token instead of refresh is rejected")
    void refreshRejectsAccessToken() throws Exception {
        register(USER_ID, LOGIN, PASSWORD);
        String accessToken = login(LOGIN, PASSWORD).accessToken();

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + accessToken + "\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void validateRejectsGarbageTokenWithoutError500() throws Exception {
        mockMvc.perform(post("/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"not-a-jwt\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.reason").isNotEmpty());
    }

    @Test
    void duplicateLoginReturns409() throws Exception {
        register(USER_ID, LOGIN, PASSWORD);

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(USER_ID + 1, LOGIN, PASSWORD)))
                .andExpect(status().isConflict());
    }

    @Test
    void duplicateUserIdReturns409() throws Exception {
        register(USER_ID, LOGIN, PASSWORD);

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(USER_ID, "another", PASSWORD)))
                .andExpect(status().isConflict());
    }

    @Test
    void protectedEndpointRejectsMissingToken() throws Exception {
        mockMvc.perform(get("/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    @DisplayName("GET /auth/credentials/{userId} is forbidden for USER role")
    void credentialsEndpointForbiddenForUserRole() throws Exception {
        register(USER_ID, LOGIN, PASSWORD);
        String accessToken = login(LOGIN, PASSWORD).accessToken();

        mockMvc.perform(get("/auth/credentials/{userId}", USER_ID)
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void malformedJsonReturns400Not500() throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{broken json"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("blank login violates @NotBlank and @Size, error names the field")
    void registerBlankLoginRejectedWithFieldName() throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(USER_ID, "  ", PASSWORD)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.login").isNotEmpty());
    }

    @Test
    void registerShortLoginRejected() throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(USER_ID, "ab", PASSWORD)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.login").isNotEmpty());
    }

    @Test
    void registerTooLongLoginRejected() throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(USER_ID, "l".repeat(51), PASSWORD)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.login").isNotEmpty());
    }

    @Test
    @DisplayName("blank password violates @NotBlank and @Size, error names the field")
    void registerBlankPasswordRejectedWithFieldName() throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(USER_ID, LOGIN, "  ")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").isNotEmpty());
    }

    @Test
    void registerShortPasswordRejected() throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(USER_ID, LOGIN, "short")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").isNotEmpty());
    }

    @Test
    void registerMissingUserIdRejected() throws Exception {
        String body = "{\"login\":\"" + LOGIN + "\",\"password\":\"" + PASSWORD + "\"}";
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.userId").isNotEmpty());
    }
}
