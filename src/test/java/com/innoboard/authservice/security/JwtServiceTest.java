package com.innoboard.authservice.security;

import com.innoboard.authservice.config.JwtProperties;
import com.innoboard.authservice.domain.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("JwtService: RS256 token generation and parsing")
class JwtServiceTest {

    private static final Long USER_ID = 1L;
    private static final String KEY_ID = "test-key";

    private final KeyPair keyPair = generateKeyPair();
    private final JwtService jwtService = jwtService(keyPair, KEY_ID);

    @Test
    @DisplayName("access token round-trips user_id, role and type claims")
    void accessTokenRoundTrip() {
        String token = jwtService.generateAccessToken(USER_ID, Role.USER);

        Claims claims = jwtService.parseToken(token);

        assertThat(jwtService.extractUserId(claims)).isEqualTo(USER_ID);
        assertThat(jwtService.extractRole(claims)).isEqualTo(Role.USER);
        assertThat(jwtService.extractType(claims)).isEqualTo(JwtService.ACCESS_TOKEN_TYPE);
    }

    @Test
    @DisplayName("refresh token carries type=refresh")
    void refreshTokenHasRefreshType() {
        String token = jwtService.generateRefreshToken(USER_ID, Role.USER);

        Claims claims = jwtService.parseToken(token);

        assertThat(jwtService.extractType(claims)).isEqualTo(JwtService.REFRESH_TOKEN_TYPE);
    }

    @Test
    @DisplayName("tokens are signed with RS256 and carry the kid header")
    void tokenSignedWithRs256AndKeyId() {
        String token = jwtService.generateAccessToken(USER_ID, Role.USER);

        Jws<Claims> parsed = Jwts.parser()
                .verifyWith(keyPair.getPublic())
                .build()
                .parseSignedClaims(token);

        assertThat(parsed.getHeader().getAlgorithm()).isEqualTo("RS256");
        assertThat(parsed.getHeader().getKeyId()).isEqualTo(KEY_ID);
    }

    @Test
    @DisplayName("public key rebuilt from jwks.json verifies an issued token")
    void jwksKeyVerifiesIssuedToken() throws Exception {
        Map<String, Object> jwk = jwk();
        assertThat(jwk.get("kty")).isEqualTo("RSA");
        assertThat(jwk.get("alg")).isEqualTo("RS256");
        assertThat(jwk.get("use")).isEqualTo("sig");
        assertThat(jwk.get("kid")).isEqualTo(KEY_ID);
        RSAPublicKeySpec spec = new RSAPublicKeySpec(
                new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("n"))),
                new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("e"))));
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);

        String token = jwtService.generateAccessToken(USER_ID, Role.USER);

        Claims claims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        assertThat(jwtService.extractUserId(claims)).isEqualTo(USER_ID);
        assertThat(jwtService.extractRole(claims)).isEqualTo(Role.USER);
    }

    @Test
    @DisplayName("expired token is rejected")
    void expiredTokenRejected() {
        JwtService expiredService = new JwtService(new JwtProperties(
                pem(keyPair.getPrivate().getEncoded(), "PRIVATE KEY"),
                pem(keyPair.getPublic().getEncoded(), "PUBLIC KEY"),
                KEY_ID,
                Duration.ofSeconds(-60),
                Duration.ofSeconds(-60)));

        String token = expiredService.generateAccessToken(USER_ID, Role.USER);

        assertThatThrownBy(() -> jwtService.parseToken(token))
                .isInstanceOf(ExpiredJwtException.class);
    }

    @Test
    @DisplayName("token signed with a different key is rejected")
    void foreignSignatureRejected() {
        JwtService otherService = jwtService(generateKeyPair(), "other-key");

        String token = otherService.generateAccessToken(USER_ID, Role.USER);

        assertThatThrownBy(() -> jwtService.parseToken(token))
                .isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("garbage string causes JwtException")
    void garbageStringRejected() {
        assertThatThrownBy(() -> jwtService.parseToken("not-a-jwt"))
                .isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("missing user_id claim is IllegalArgumentException, not NPE")
    void missingUserIdClaimRejected() {
        String token = Jwts.builder()
                .header().keyId(KEY_ID).and()
                .claim(JwtService.TYPE_CLAIM, JwtService.ACCESS_TOKEN_TYPE)
                .expiration(Date.from(Instant.now().plusSeconds(60)))
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();
        Claims claims = jwtService.parseToken(token);

        assertThatThrownBy(() -> jwtService.extractUserId(claims))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("missing role claim is IllegalArgumentException, not NPE")
    void missingRoleClaimRejected() {
        String token = Jwts.builder()
                .header().keyId(KEY_ID).and()
                .claim(JwtService.USER_ID_CLAIM, USER_ID)
                .claim(JwtService.TYPE_CLAIM, JwtService.ACCESS_TOKEN_TYPE)
                .expiration(Date.from(Instant.now().plusSeconds(60)))
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();
        Claims claims = jwtService.parseToken(token);

        assertThatThrownBy(() -> jwtService.extractRole(claims))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("malformed key material fails at construction")
    void malformedKeyRejected() {
        assertThatThrownBy(() -> new JwtService(new JwtProperties(
                new ByteArrayResource("junk".getBytes(StandardCharsets.UTF_8)),
                new ByteArrayResource("junk".getBytes(StandardCharsets.UTF_8)),
                KEY_ID,
                Duration.ofSeconds(900),
                Duration.ofSeconds(604800))))
                .isInstanceOf(RuntimeException.class);
    }

    private Map<String, Object> jwk() {
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) jwtService.getJwks().get("keys");
        return keys.get(0);
    }

    private static JwtService jwtService(KeyPair keyPair, String keyId) {
        return new JwtService(new JwtProperties(
                pem(keyPair.getPrivate().getEncoded(), "PRIVATE KEY"),
                pem(keyPair.getPublic().getEncoded(), "PUBLIC KEY"),
                keyId,
                Duration.ofSeconds(900),
                Duration.ofSeconds(604800)));
    }

    private static Resource pem(byte[] encoded, String type) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(encoded);
        String pem = "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n";
        return new ByteArrayResource(pem.getBytes(StandardCharsets.UTF_8));
    }

    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
