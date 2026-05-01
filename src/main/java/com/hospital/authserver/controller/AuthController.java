package com.hospital.authserver.controller;

import com.hospital.authserver.dto.AuthenticationResponse;
import com.hospital.authserver.dto.UserLoginRequest;
import com.hospital.authserver.dto.UserRegistrationRequest;
import com.hospital.authserver.dto.UserRegistrationResponse;
import com.hospital.authserver.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<UserRegistrationResponse> register(@RequestBody UserRegistrationRequest request) {
        try {
            log.info("Registration attempt for email: {}", request.getEmail());
            UserRegistrationResponse response = authService.register(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (IllegalArgumentException e) {
            log.warn("Registration failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        } catch (Exception e) {
            log.error("Unexpected error during registration", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody UserLoginRequest request) {
        try {
            log.info("Login attempt for email: {}", request.getEmail());
            AuthenticationResponse response = authService.login(request);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            log.warn("Login failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception e) {
            log.error("Unexpected error during login", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

   // @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader(name = "Authorization", required = false) String authorizationHeader) {
       
    	System.out.println("from logout");
    	try {
            if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
                log.warn("Logout attempt missing or invalid Authorization header");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }

            String accessToken = authorizationHeader.substring(7);
            log.info("Logout attempt for access token");
            authService.revokeTokensByAccessToken(accessToken);
            return ResponseEntity.ok().build();
        } catch (IllegalArgumentException e) {
            log.warn("Logout failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        } catch (Exception e) {
            log.error("Error during logout", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/logout/{userId}")
    public ResponseEntity<Void> logoutByUserId(@PathVariable Long userId) {
        try {
            log.info("Logout for user: {}", userId);
            authService.revokeTokens(userId);
            return ResponseEntity.ok().build();
        } catch (IllegalArgumentException e) {
            log.warn("Logout failed for user {}: {}", userId, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        } catch (Exception e) {
            log.error("Error during logout", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}

