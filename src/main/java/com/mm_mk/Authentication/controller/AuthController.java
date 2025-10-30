package com.mm_mk.Authentication.controller;

import com.mm_mk.Authentication.request.RegisterRequest;
import com.mm_mk.Authentication.request.UpdateUserRequest;
import com.mm_mk.Authentication.response.AuthenticationResult;
import com.mm_mk.Authentication.response.UserResponse;
import com.mm_mk.Authentication.service.AuthService;
import com.mm_mk.Authentication.util.CorrelationIdUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "APIs for user authentication and registration")
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private static final long SLOW_OPERATION_THRESHOLD_MS = 2000;
    private final AuthService authService;

    @PostMapping("/register")
    @Operation(summary = "Register new user", description = "Create user account with username, email, password")
    @ApiResponse(responseCode = "201", description = "User registered successfully")
    @ApiResponse(responseCode = "400", description = "Invalid input data")
    @ApiResponse(responseCode = "409", description = "Username already exists")
    public ResponseEntity<AuthenticationResult> register(@Valid @RequestBody RegisterRequest req) {
        long startTime = System.currentTimeMillis();
        String correlationId = CorrelationIdUtil.getCorrelationId();
        logger.info("REGISTER request - correlationId: {}, username: {}, email: {}", correlationId, req.username(), req.email());

        try {
            AuthenticationResult result = authService.register(req);
            logger.info("REGISTER success - correlationId: {}, username: {}, userId: {}", correlationId, req.username(), result.user().id());
            return ResponseEntity.status(HttpStatus.CREATED).body(result);
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            logger.info("REGISTER API call completed in {}ms - correlationId: {}", duration, correlationId);
            if (duration > SLOW_OPERATION_THRESHOLD_MS)
                logger.warn("SLOW API: REGISTER took {}ms - correlationId: {}", duration, correlationId);
        }
    }

    @PutMapping("/{userId}")
    @Operation(summary = "Update user profile", description = "Update username or keyboard preference")
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponse(responseCode = "200", description = "User updated successfully")
    @ApiResponse(responseCode = "403", description = "Can only update own profile")
    public ResponseEntity<UserResponse> updateUser(@PathVariable UUID userId, @Valid @RequestBody UpdateUserRequest updateRequest, Authentication authentication) {
        long startTime = System.currentTimeMillis();
        String correlationId = CorrelationIdUtil.getCorrelationId();
        logger.info("UPDATE_USER request - correlationId: {}, userId: {}, newUsername: {}, newKeyboard: {}", correlationId, userId, updateRequest.username(), updateRequest.preferredKeyboard());

        try {
            UserResponse userResponse = authService.update(userId, updateRequest, authentication);
            logger.info("UPDATE_USER success - correlationId: {}, userId: {}, username: {}", correlationId, userId, userResponse.username());
            return ResponseEntity.ok(userResponse);
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            logger.info("UPDATE_USER API call completed in {}ms - correlationId: {}", duration, correlationId);
            if (duration > SLOW_OPERATION_THRESHOLD_MS)
                logger.warn("SLOW API: UPDATE_USER took {}ms - correlationId: {}", duration, correlationId);
        }
    }
}