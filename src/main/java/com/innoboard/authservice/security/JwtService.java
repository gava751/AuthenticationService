package com.innoboard.authservice.security;

import com.innoboard.authservice.config.JwtProperties;
import com.innoboard.authservice.domain.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.Resource;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Component
public class JwtService {

    public static final String USER_ID_CLAIM = "user_id";
    public static final String TYPE_CLAIM = "type";
    public static final String ROLE_CLAIM = "role";
    public static final String ACCESS_TOKEN_TYPE = "access";
    public static final String REFRESH_TOKEN_TYPE = "refresh";

    private final JwtProperties properties;
    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final Map<String, Object> jwks;

    public JwtService(JwtProperties properties) {
        this.properties = properties;
        this.privateKey = readPrivateKey(properties.privateKey());
        this.publicKey = readPublicKey(properties.publicKey());
        this.jwks = buildJwks();
    }

    public String generateAccessToken(Long userId, Role role) {
        return buildToken(userId, role, ACCESS_TOKEN_TYPE, properties.accessTokenTtl());
    }

    public String generateRefreshToken(Long userId, Role role) {
        return buildToken(userId, role, REFRESH_TOKEN_TYPE, properties.refreshTokenTtl());
    }

    public Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Long extractUserId(Claims claims) {
        if (claims.get(USER_ID_CLAIM) instanceof Number number) {
            return number.longValue();
        }
        throw new IllegalArgumentException("Missing or invalid user_id claim");
    }

    public Role extractRole(Claims claims) {
        String role = claims.get(ROLE_CLAIM, String.class);
        if (role == null) {
            throw new IllegalArgumentException("Missing role claim");
        }
        return Role.valueOf(role);
    }

    public String extractType(Claims claims) {
        return claims.get(TYPE_CLAIM, String.class);
    }

    public Map<String, Object> getJwks() {
        return jwks;
    }

    private Map<String, Object> buildJwks() {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("use", "sig");
        jwk.put("alg", "RS256");
        jwk.put("kid", properties.keyId());
        jwk.put("n", encoder.encodeToString(minimalBytes(publicKey.getModulus())));
        jwk.put("e", encoder.encodeToString(minimalBytes(publicKey.getPublicExponent())));
        return Map.of("keys", List.of(jwk));
    }

    private static byte[] minimalBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    private String buildToken(Long userId, Role role, String type, Duration ttl) {
        Instant now = Instant.now();
        return Jwts.builder()
                .header().keyId(properties.keyId()).and()
                .claim(USER_ID_CLAIM, userId)
                .claim(ROLE_CLAIM, role.name())
                .claim(TYPE_CLAIM, type)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(ttl)))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    private RSAPrivateKey readPrivateKey(Resource resource) {
        Converter<InputStream, ? extends RSAPrivateKey> converter = RsaKeyConverters.pkcs8();
        try (InputStream in = resource.getInputStream()) {
            return converter.convert(in);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read JWT private key: " + resource, e);
        }
    }

    private RSAPublicKey readPublicKey(Resource resource) {
        Converter<InputStream, ? extends RSAPublicKey> converter = RsaKeyConverters.x509();
        try (InputStream in = resource.getInputStream()) {
            return converter.convert(in);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read JWT public key: " + resource, e);
        }
    }
}
