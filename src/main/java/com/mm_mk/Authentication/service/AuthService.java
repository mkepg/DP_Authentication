package com.mm_mk.Authentication.service;

import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
import com.mm_mk.Authentication.request.RegisterRequest;
import com.mm_mk.Authentication.request.UpdateUserRequest;
import com.mm_mk.Authentication.response.AuthenticationResult;
import com.mm_mk.Authentication.response.UserResponse;
import com.mm_mk.Authentication.util.CorrelationIdUtil;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private static final long SLOW_OPERATION_THRESHOLD_MS = 1000;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    @Transactional
    public AuthenticationResult register(RegisterRequest req) {
        long startTime = System.currentTimeMillis();
        String correlationId = CorrelationIdUtil.getCorrelationId();
        logger.info("REGISTER service - correlationId: {}, username: {}, email: {}", correlationId, req.username(), req.email());

        try {
            if (userRepository.existsByUsername(req.username())) {
                logger.warn("Username already exists - correlationId: {}, username: {}", correlationId, req.username());
                throw new IllegalArgumentException("Username already exists");
            }

            User user = userService.createUser(req.username(), req.email(), passwordEncoder.encode(req.password()));
            UserResponse userResponse = new UserResponse(user.getId(), user.getUsername(), user.getEmail(), user.getPreferredKeyboard());
            logger.info("REGISTER service success - correlationId: {}, username: {}, userId: {}", correlationId, user.getUsername(), user.getId());
            return new AuthenticationResult("Register successful", userResponse);
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            logger.debug("REGISTER service completed in {}ms - correlationId: {}", duration, correlationId);
            if (duration > SLOW_OPERATION_THRESHOLD_MS)
                logger.warn("SLOW OPERATION: REGISTER service took {}ms - correlationId: {}", duration, correlationId);
        }
    }

    public UserResponse update(UUID userId, UpdateUserRequest updateRequest, Authentication authentication) {
        long startTime = System.currentTimeMillis();
        String correlationId = CorrelationIdUtil.getCorrelationId();
        logger.info("UPDATE_USER service - correlationId: {}, userId: {}, newUsername: {}, newKeyboard: {}", correlationId, userId, updateRequest.username(), updateRequest.preferredKeyboard());

        try {
            if (authentication == null || !authentication.isAuthenticated()) {
                logger.warn("User not authenticated - correlationId: {}, userId: {}", correlationId, userId);
                throw new IllegalArgumentException("User not authenticated");
            }

            Jwt jwt = (Jwt) authentication.getPrincipal();
            String tokenUserId = jwt.getSubject();

            logger.debug("JWT token details - correlationId: {}, subject: {}, claims: {}", correlationId, tokenUserId, jwt.getClaims());

            if (!userId.toString().equals(tokenUserId)) {
                logger.warn("User attempted to update another user's profile - correlationId: {}, requestedUserId: {}, authenticatedUserId: {}", correlationId, userId, tokenUserId);
                throw new IllegalArgumentException("You can only update your own profile");
            }

            logger.debug("User authorization validated - correlationId: {}, userId: {}", correlationId, userId);
            var updatedUser = userService.updateUser(userId, updateRequest);
            logger.info("UPDATE_USER service success - correlationId: {}, userId: {}, newUsername: {}", correlationId, userId, updatedUser.getUsername());
            return new UserResponse(updatedUser.getId(), updatedUser.getUsername(), updatedUser.getEmail(), updatedUser.getPreferredKeyboard());
        } catch (IllegalArgumentException e) {
            logger.error("UPDATE_USER service failed - correlationId: {}, userId: {}, error: {}", correlationId, userId, e.getMessage());
            throw e;
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            logger.debug("UPDATE_USER service completed in {}ms - correlationId: {}", duration, correlationId);
            if (duration > SLOW_OPERATION_THRESHOLD_MS)
                logger.warn("SLOW OPERATION: UPDATE_USER service took {}ms - correlationId: {}", duration, correlationId);
        }
    }
}
