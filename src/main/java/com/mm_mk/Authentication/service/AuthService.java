package com.mm_mk.Authentication.service;

import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
import com.mm_mk.Authentication.request.RegisterRequest;
import com.mm_mk.Authentication.request.UpdateUserRequest;
import com.mm_mk.Authentication.response.AuthenticationResult;
import com.mm_mk.Authentication.response.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    @Transactional
    public AuthenticationResult register(RegisterRequest req) {
        if (userRepository.existsByUsername(req.username()))
            throw new IllegalArgumentException("Username already exists");

        User user = userService.createUser(req.username(), req.email(), passwordEncoder.encode(req.password()));
        UserResponse userResponse = new UserResponse(user.getId() ,user.getUsername(), user.getEmail(), user.getPreferredKeyboard());

        return new AuthenticationResult("Register successful", userResponse);
    }

    public UserResponse update(UUID userId, UpdateUserRequest updateRequest, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated())
            throw new IllegalArgumentException("User not authenticated");

        Jwt jwt = (Jwt) authentication.getPrincipal();
        String tokenUserId = jwt.getClaimAsString("user_id");

        if (tokenUserId == null) {
            String username = jwt.getSubject();
            User user = userRepository.findByUsername(username).orElseThrow(() -> new IllegalArgumentException("User not found"));
            tokenUserId = user.getId().toString();
        }

        if (!userId.toString().equals(tokenUserId))
            throw new IllegalArgumentException("You can only update your own profile");

        var updatedUser = userService.updateUser(userId, updateRequest);

        return new UserResponse(updatedUser.getId(), updatedUser.getUsername(), updatedUser.getEmail(), updatedUser.getPreferredKeyboard());
    }
}

