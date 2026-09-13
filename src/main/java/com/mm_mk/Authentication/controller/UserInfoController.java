package com.mm_mk.Authentication.controller;

import com.mm_mk.Authentication.repository.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
@Tag(name = "User Info", description = "Get current user information from JWT")
public class UserInfoController {

    private final UserRepository userRepository;

    @GetMapping("/userinfo")
    @Operation(summary = "Get user info", description = "Returns current user details from JWT token")
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponse(responseCode = "200", description = "User info retrieved successfully")
    public Map<String, Object> userInfo(Authentication authentication) {
        Map<String, Object> userInfo = new HashMap<>();

        if (authentication.getPrincipal() instanceof Jwt jwt) {
            String subject = jwt.getSubject();

            try {
                UUID userId = UUID.fromString(subject);
                userRepository.findById(userId).ifPresent(user -> {
                    userInfo.put("sub", user.getId().toString());
                    userInfo.put("username", user.getUsername());
                    userInfo.put("user_id", user.getId().toString());
                    userInfo.put("email", user.getEmail());
                    userInfo.put("preferred_keyboard", user.getPreferredKeyboard().name());
                });
            } catch (IllegalArgumentException e) {
                String username = subject;
                userRepository.findByUsername(username).ifPresent(user -> {
                    userInfo.put("sub", user.getId().toString());
                    userInfo.put("username", user.getUsername());
                    userInfo.put("user_id", user.getId().toString());
                    userInfo.put("email", user.getEmail());
                    userInfo.put("preferred_keyboard", user.getPreferredKeyboard().name());
                });
            }
        }

        return userInfo;
    }
}
