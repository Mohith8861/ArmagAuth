package com.example.ArmagBackend.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JWTService {

    private static final String SECRET = "83d2af1d7f2953d30918ec4485cc9cfff722966e5a0ee19ad6a66c3be3425328";

    private long accessTokenExpiry = 60000L;
    private long refreshTokenExpiry = 180000L;

    @Value("${jwt.accessExpirationTime}")
    public void setAccessExpirationTime(long accessExpirationTime) {
        this.accessTokenExpiry = accessExpirationTime;
    }

    @Value("${jwt.refreshExpirationTime}")
    public void setRefreshExpirationTime(long refreshExpirationTime) {
        this.refreshTokenExpiry = refreshExpirationTime;
    }

    public String generateAccessToken(String username) {
        return createToken(new HashMap<>(), username, accessTokenExpiry);
    }

    public String generateRefreshToken(String username) {
        return createToken(new HashMap<>(), username, refreshTokenExpiry);
    }

    private String createToken(Map<String, Object> claims, String subject, long expiration) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build().parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String refreshAccessToken(String refreshToken) {
        if (isTokenExpired(refreshToken)) {
            throw new RuntimeException("Refresh token has expired");
        }
        final String username = extractUserName(refreshToken);
        return generateAccessToken(username);
    }

    public TokenPair generateTokenPair(String username) {
        String accessToken = generateAccessToken(username);
        String refreshToken = generateRefreshToken(username);
        return new TokenPair(accessToken, refreshToken);
    }

    public static class TokenPair {
        public final String accessToken;
        public final String refreshToken;

        public TokenPair(String accessToken, String refreshToken) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }
    }
}