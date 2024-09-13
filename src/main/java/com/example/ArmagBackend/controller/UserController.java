package com.example.ArmagBackend.controller;


import com.example.ArmagBackend.model.User;
import com.example.ArmagBackend.service.JWTService;
import com.example.ArmagBackend.service.UserService;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;


@RestController
@RequestMapping("/auth")
public class UserController {

    @Autowired
    private UserService service;

    @Autowired
    private JWTService jwtService;

    @Autowired
    AuthenticationManager authenticationManager;

    @PostMapping("/signup")
    public ResponseEntity<?> register(@RequestBody User user) {
        User registeredUser = service.saveUser(user);
        try {
            JWTService.TokenPair tokenPair = jwtService.generateTokenPair(user.getUsername());
            return ResponseEntity.ok(new AuthResponse(user.getUsername(), "success", tokenPair.accessToken, tokenPair.refreshToken));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
            );
            if (authentication.isAuthenticated()) {
                JWTService.TokenPair tokenPair = jwtService.generateTokenPair(user.getUsername());
                return ResponseEntity.ok(new AuthResponse(user.getUsername(), "success", tokenPair.accessToken, tokenPair.refreshToken));
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse("Authentication failed"));
            }
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse("Invalid username or password"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        try {
            String newAccessToken = jwtService.refreshAccessToken(refreshTokenRequest.getRefreshToken());
            return ResponseEntity.ok(new AccessTokenResponse(newAccessToken));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse("Invalid or expired refresh token"));
        }
    }

    @GetMapping("/test")
    public ResponseEntity<String> authenticatedEndpoint() {
        return ResponseEntity.ok("You are authorized");
    }

    @Data
    @AllArgsConstructor
    private static class AuthResponse {
        private String user;
        private String status;
        private String accessToken;
        private String refreshToken;
    }

    @Data
    @AllArgsConstructor
    private static class ErrorResponse {
        private String message;
    }

    @Data
    private static class RefreshTokenRequest {
        private String refreshToken;
    }

    @Data
    @AllArgsConstructor
    private static class AccessTokenResponse {
        private String accessToken;
    }
}