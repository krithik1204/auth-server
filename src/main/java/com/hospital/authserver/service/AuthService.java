package com.hospital.authserver.service;

import com.hospital.authserver.dto.AuthenticationResponse;
import com.hospital.authserver.dto.UserLoginRequest;
import com.hospital.authserver.dto.UserRegistrationRequest;
import com.hospital.authserver.entity.User;
import com.hospital.authserver.entity.UserToken;
import com.hospital.authserver.repository.UserRepository;
import com.hospital.authserver.repository.UserTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final UserTokenRepository userTokenRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public AuthenticationResponse register(UserRegistrationRequest request) {
        // Validate email uniqueness
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email already registered");
        }

        // Validate medical record number uniqueness
        if (userRepository.existsByMedicalRecordNumber(request.getMedicalRecordNumber())) {
            throw new IllegalArgumentException("Medical record number already exists");
        }

        // Create new user
        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPhoneNumber(request.getPhoneNumber());
        user.setMedicalRecordNumber(request.getMedicalRecordNumber());

        user = userRepository.save(user);
        log.info("User registered successfully with email: {}", request.getEmail());

        // Generate tokens
        return generateTokensForUser(user);
    }

    public AuthenticationResponse login(UserLoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Invalid email or password");
        }

        log.info("User logged in successfully with email: {}", request.getEmail());

        // Generate tokens
        return generateTokensForUser(user);
    }

    private AuthenticationResponse generateTokensForUser(User user) {
        // Generate JWT tokens
        String accessToken = jwtService.generateAccessToken(user.getId(), user.getEmail());
        String refreshToken = jwtService.generateRefreshToken(user.getId(), user.getEmail());

        // Save token to database
        UserToken token = new UserToken();
        token.setUser(user);
        token.setAccessToken(accessToken);
        token.setRefreshToken(refreshToken);
        token.setIssuedAt(LocalDateTime.now());
        token.setExpiresAt(LocalDateTime.now().plus(jwtService.getAccessTokenExpirationDuration()));
        token.setRevoked(false);

        userTokenRepository.save(token);

        // Build response
        AuthenticationResponse response = new AuthenticationResponse();
        response.setAccessToken(accessToken);
        response.setRefreshToken(refreshToken);
        response.setTokenType("Bearer");
        response.setExpiresIn(jwtService.getAccessTokenExpiration());

        // Build user DTO
        AuthenticationResponse.UserDto userDto = new AuthenticationResponse.UserDto();
        userDto.setId(user.getId());
        userDto.setEmail(user.getEmail());
        userDto.setFirstName(user.getFirstName());
        userDto.setLastName(user.getLastName());
        userDto.setMedicalRecordNumber(user.getMedicalRecordNumber());

        response.setUser(userDto);

        return response;
    }

    public void revokeTokens(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        userTokenRepository.findByUserAndRevokedFalse(user)
                .forEach(token -> {
                    token.setRevoked(true);
                    userTokenRepository.save(token);
                });

        log.info("Tokens revoked for user: {}", userId);
    }
}
