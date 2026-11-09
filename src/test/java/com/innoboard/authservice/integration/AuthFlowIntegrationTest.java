package com.innoboard.authservice.integration;

import com.innoboard.authservice.client.UserClient;
import com.innoboard.authservice.dto.CreateUserRequest;
import com.innoboard.authservice.dto.LoginRequest;
import com.innoboard.authservice.dto.RegisterCredentialsRequest;
import com.innoboard.authservice.exception.DuplicateCredentialsException;
import com.innoboard.authservice.exception.UserCreationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DisplayName("Integration flow: register -> login -> refresh -> me")
class AuthFlowIntegrationTest extends IntegrationTestBase {

    @Test
    void registerReturnsCreatedCredentialsWithDefaultUserRole() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(LOGIN, PASSWORD)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.userId").value(USER_ID))
                .andExpect(jsonPath("$.username").value(LOGIN))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.createdAt").isNotEmpty());
    }

    @Test
    void loginReturnsBothTokens() throws Exception {
        register(LOGIN, PASSWORD);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(LOGIN, PASSWORD))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").isNumber());
    }

    @Test
    void meReturnsAuthenticatedUser() throws Exception {
        register(LOGIN, PASSWORD);
        String accessToken = login(LOGIN, PASSWORD).accessToken();

        mockMvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(USER_ID))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void refreshReturnsUsableNewTokens() throws Exception {
        register(LOGIN, PASSWORD);
        Tokens old = login(LOGIN, PASSWORD);

        String body = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + old.refreshToken() + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        Tokens fresh = objectMapper.readValue(body, Tokens.class);

        mockMvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + fresh.accessToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(USER_ID));
    }

    @Test
    @DisplayName("access token instead of refresh is rejected")
    void refreshRejectsAccessToken() throws Exception {
        register(LOGIN, PASSWORD);
        String accessToken = login(LOGIN, PASSWORD).accessToken();

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + accessToken + "\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void jwksEndpointIsPublicAndExposesRsaKey() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].kid").value("test-key"));
    }

    @Test
    void validateEndpointIsRemoved() throws Exception {
        mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"anything\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void duplicateLoginReturns409() throws Exception {
        register(LOGIN, PASSWORD);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(LOGIN, PASSWORD)))
                .andExpect(status().isConflict());
    }

    @Test
    void duplicateEmailInUserServiceReturns409() throws Exception {
        when(userClient.createUser(any())).thenThrow(
                new DuplicateCredentialsException("Email already registered"));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson("another", PASSWORD)))
                .andExpect(status().isConflict());
    }

    @Test
    void unavailableUserServiceReturns502() throws Exception {
        when(userClient.createUser(any())).thenThrow(new UserCreationException("User Service is unavailable"));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(LOGIN, PASSWORD)))
                .andExpect(status().isBadGateway());
    }

    @Test
    void protectedEndpointRejectsMissingToken() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    @DisplayName("GET /api/auth/credentials/{userId} is forbidden for USER role")
    void credentialsEndpointForbiddenForUserRole() throws Exception {
        register(LOGIN, PASSWORD);
        String accessToken = login(LOGIN, PASSWORD).accessToken();

        mockMvc.perform(get("/api/auth/credentials/{userId}", USER_ID)
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void malformedJsonReturns400Not500() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{broken json"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("client errors: unsupported Content-Type is 415, not 500")
    void unsupportedMediaTypeReturns415Not500() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content(registerJson(LOGIN, PASSWORD)))
                .andExpect(status().isUnsupportedMediaType());
    }

    @Test
    @DisplayName("blank login violates @NotBlank and @Size, error names the field")
    void registerBlankLoginRejectedWithFieldName() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson("  ", PASSWORD)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.login").isNotEmpty());
    }

    @Test
    void registerShortLoginRejected() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson("ab", PASSWORD)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.login").isNotEmpty());
    }

    @Test
    void registerTooLongLoginRejected() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson("l".repeat(51), PASSWORD)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.login").isNotEmpty());
    }

    @Test
    @DisplayName("blank password violates @NotBlank and @Size, error names the field")
    void registerBlankPasswordRejectedWithFieldName() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(LOGIN, "  ")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").isNotEmpty());
    }

    @Test
    void registerShortPasswordRejected() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(LOGIN, "short")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").isNotEmpty());
    }

    @Test
    @DisplayName("missing profile field is reported by name")
    void registerMissingNameRejected() throws Exception {
        String body = "{\"login\":\"" + LOGIN + "\",\"password\":\"" + PASSWORD + "\","
                + "\"surname\":\"" + SURNAME + "\",\"birthDate\":\"1990-01-01\",\"email\":\"" + EMAIL + "\"}";
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.name").isNotEmpty());
    }

    @Test
    @DisplayName("past birth date is required")
    void registerFutureBirthDateRejected() throws Exception {
        String body = "{\"login\":\"" + LOGIN + "\",\"password\":\"" + PASSWORD + "\","
                + "\"name\":\"" + NAME + "\",\"surname\":\"" + SURNAME + "\","
                + "\"birthDate\":\"2999-01-01\",\"email\":\"" + EMAIL + "\"}";
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.birthDate").isNotEmpty());
    }

    @Test
    @DisplayName("invalid email violates @Email, error names the field")
    void registerInvalidEmailRejected() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(new RegisterCredentialsRequest(
                                LOGIN, PASSWORD, NAME, SURNAME, BIRTH_DATE, "not-an-email"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email").isNotEmpty());
    }

    @Test
    @DisplayName("blank surname violates @NotBlank, error names the field")
    void registerBlankSurnameRejected() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(new RegisterCredentialsRequest(
                                LOGIN, PASSWORD, NAME, "  ", BIRTH_DATE, EMAIL))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.surname").isNotEmpty());
    }

    @Test
    @DisplayName("login: blank login and password are rejected with field names")
    void loginBlankFieldsRejected() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\" \",\"password\":\" \"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.login").isNotEmpty())
                .andExpect(jsonPath("$.errors.password").isNotEmpty());
    }

    @Test
    @DisplayName("refresh: blank refreshToken is rejected with field name")
    void refreshBlankTokenRejected() throws Exception {
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\" \"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.refreshToken").isNotEmpty());
    }

    @Test
    @DisplayName("refresh is indistinguishable: broken token, access-token and missing account share one 401 text")
    void refreshIsNotAnAccountStateOracle() throws Exception {
        register(LOGIN, PASSWORD);
        String accessToken = login(LOGIN, PASSWORD).accessToken();

        String brokenMessage = refreshMessage("not-a-token");
        String accessTypeMessage = refreshMessage(accessToken);

        assertThat(brokenMessage).isEqualTo("Invalid refresh token");
        assertThat(accessTypeMessage).isEqualTo(brokenMessage);
    }

    private String refreshMessage(String token) throws Exception {
        String body = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + token + "\"}"))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body).get("message").asText();
    }

    @Test
    @DisplayName("unexpected unique constraint is neutral 409, not 'Login already taken'")
    void unrelatedIntegrityViolationReturnsNeutralConflict() throws Exception {
        register(LOGIN, PASSWORD);
        when(userClient.createUser(any(CreateUserRequest.class))).thenReturn(USER_ID);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson("another", PASSWORD)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Data integrity constraint violated"));
    }
}
