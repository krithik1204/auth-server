package com.hospital.authserver.service;

import com.hospital.authserver.dto.AuthenticationResponse;
import com.hospital.authserver.dto.UserLoginRequest;
import com.hospital.authserver.dto.UserRegistrationRequest;
import com.hospital.authserver.dto.UserRegistrationResponse;
import com.hospital.authserver.entity.Role;
import com.hospital.authserver.entity.User;
import com.hospital.authserver.entity.UserToken;
import com.hospital.authserver.repository.RoleRepository;
import com.hospital.authserver.repository.UserRepository;
import com.hospital.authserver.repository.UserTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final UserTokenRepository userTokenRepository;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public UserRegistrationResponse register(UserRegistrationRequest request) {
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
        user.setRoles(resolveRoles(request.getRoles()));

        user = userRepository.save(user);
        log.info("User registered successfully with email: {}", request.getEmail());

        // Build response without tokens
        UserRegistrationResponse response = new UserRegistrationResponse();
        UserRegistrationResponse.UserDto userDto = new UserRegistrationResponse.UserDto();
        userDto.setId(user.getId());
        userDto.setEmail(user.getEmail());
        userDto.setFirstName(user.getFirstName());
        userDto.setLastName(user.getLastName());
        userDto.setMedicalRecordNumber(user.getMedicalRecordNumber());
        userDto.setRoles(user.getRoles().stream().map(Role::getName).collect(Collectors.toSet()));

        response.setUser(userDto);
        return response;
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
        Set<String> roleNames = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());

        // Generate JWT tokens
        String accessToken = jwtService.generateAccessToken(user.getId(), user.getEmail(), roleNames);
        String refreshToken = jwtService.generateRefreshToken(user.getId(), user.getEmail(), roleNames);

        // Save token to database
        UserToken token = new UserToken();
        token.setUser(user);
        token.setAccessToken(accessToken);
        token.setRefreshToken(refreshToken);
        token.setLoginTime(LocalDateTime.now());
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
        userDto.setRoles(roleNames);

        response.setUser(userDto);

        return response;
    }

    public void revokeTokens(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        var tokens = userTokenRepository.findByUserAndRevokedFalse(user);
        if (tokens.isEmpty()) {
            log.info("No active tokens found for user: {}", userId);
            return;
        }

        tokens.forEach(token -> {
            token.setRevoked(true);
            token.setLogoutTime(LocalDateTime.now());
            userTokenRepository.save(token);
        });

        log.info("Tokens revoked for user: {}", userId);
    }

    public void revokeTokensByAccessToken(String accessToken) {
        UserToken token = userTokenRepository.findByAccessToken(accessToken)
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired access token"));

        if (Boolean.TRUE.equals(token.getRevoked())) {
            log.info("Access token already revoked for user: {}", token.getUser().getId());
            return;
        }

        token.setRevoked(true);
        token.setLogoutTime(LocalDateTime.now());
        userTokenRepository.save(token);

        log.info("Access token revoked for user: {}", token.getUser().getId());
    }

    private Set<Role> resolveRoles(Set<String> requestedRoles) {
        Set<String> roleNames = requestedRoles == null || requestedRoles.isEmpty()
                ? Set.of("ROLE_USER")
                : requestedRoles;

        Set<Role> roles = new HashSet<>();
        for (String roleName : roleNames) {
            Role role = roleRepository.findByName(roleName)
                    .orElseGet(() -> roleRepository.save(new Role(null, roleName)));
            roles.add(role);
        }
        return roles;
    }
}
