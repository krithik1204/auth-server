package com.hospital.authserver.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    private static final long ACCESS_TOKEN_EXPIRATION = 15 * 60 * 1000; // 15 minutes
    private static final long REFRESH_TOKEN_EXPIRATION = 7 * 24 * 60 * 60 * 1000; // 7 days

    private final RSAKey rsaKey;

    @Value("${jwt.issuer:http://localhost:9000}")
    private String issuer;

    public JwtService(RSAKey rsaKey) {
        this.rsaKey = rsaKey;
    }

    private RSAPrivateKey getSigningKey() {
        try {
            return rsaKey.toRSAPrivateKey();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to get RSA private key", e);
        }
    }

    public String generateAccessToken(Long userId, String email) {
        return generateToken(userId, email, ACCESS_TOKEN_EXPIRATION);
    }

    public String generateRefreshToken(Long userId, String email) {
        return generateToken(userId, email, REFRESH_TOKEN_EXPIRATION);
    }

    private String generateToken(Long userId, String email, long expirationMs) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", email);

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .setHeaderParam("kid", rsaKey.getKeyID())
                .setClaims(claims)
                .setSubject(String.valueOf(userId))
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .setIssuer(issuer)
                .signWith(getSigningKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    public Long getAccessTokenExpiration() {
        return ACCESS_TOKEN_EXPIRATION / 1000; // Convert to seconds
    }

    public Duration getAccessTokenExpirationDuration() {
        return Duration.ofMillis(ACCESS_TOKEN_EXPIRATION);
    }

    public Duration getRefreshTokenExpirationDuration() {
        return Duration.ofMillis(REFRESH_TOKEN_EXPIRATION);
    }
}
