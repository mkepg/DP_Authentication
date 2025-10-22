package com.mm_mk.Authentication.service;

import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
import com.mm_mk.Authentication.request.LoginRequest;
import com.mm_mk.Authentication.request.RegisterRequest;
import com.mm_mk.Authentication.request.UpdateUserRequest;
import com.mm_mk.Authentication.response.AuthenticationResult;
import com.mm_mk.Authentication.response.UserDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    @Transactional
    public AuthenticationResult register(RegisterRequest req) {
        if (userRepository.existsByUsername(req.username())) {
            throw new IllegalArgumentException("Username already exists");
        }

        // Use the original 3-argument version - let database handle default
        User user = userService.createUser(
                req.username(),
                req.email(),
                passwordEncoder.encode(req.password())
        );

        UserDTO userDTO = new UserDTO(user.getId() ,user.getUsername(), user.getEmail(), user.getPreferredKeyboard());

        return new AuthenticationResult("Register successful", userDTO);

    }

    public UserDTO update(UUID userId, UpdateUserRequest updateRequest, Authentication authentication) {
        // Check authentication
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalArgumentException("User not authenticated");
        }

        // Extract JWT and get user_id claim
        Jwt jwt = (Jwt) authentication.getPrincipal();
        String tokenUserId = jwt.getClaimAsString("user_id");

        // Fallback: try subject if user_id claim missing
        if (tokenUserId == null) {
            String username = jwt.getSubject();
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new IllegalArgumentException("User not found"));
            tokenUserId = user.getId().toString();
        }

        // Only allow users to update their own profile
        if (!userId.toString().equals(tokenUserId)) {
            throw new IllegalArgumentException("You can only update your own profile");
        }

        // Perform update
        var updatedUser = userService.updateUser(userId, updateRequest);

        return new UserDTO(
                updatedUser.getId(),
                updatedUser.getUsername(),
                updatedUser.getEmail(),
                updatedUser.getPreferredKeyboard()
        );
    }
}

