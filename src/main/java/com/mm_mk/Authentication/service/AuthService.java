// src/main/java/com/mm_mk/DP/Authentication/service/AuthService.java
package com.mm_mk.Authentication.service;

import com.mm_mk.Authentication.event.UserCreatedEvent;
import com.mm_mk.Authentication.repository.UserRepository;
import com.mm_mk.Authentication.response.AuthenticationResult;
import com.mm_mk.Authentication.security.JpaUserDetailsService;
import com.mm_mk.Authentication.security.JwtUtils;
import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.request.LoginRequest;
import com.mm_mk.Authentication.request.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository repo;
    private final PasswordEncoder encoder;
    private final JpaUserDetailsService jpaUserDetailsService;
    private final JwtUtils jwtUtils;
    private final RabbitTemplate rabbitTemplate;

    /**
     * Handles user registration
     */
    @Transactional
    public AuthenticationResult register(RegisterRequest req) {
        if (repo.existsByUsername(req.username())) {
            throw new IllegalArgumentException("Username already exists");
        }

        User user = User.builder()
                .username(req.username())
                .passwordHash(encoder.encode(req.password()))
                .email(req.email())
                .build();

        repo.save(user);

        // Publish event to RabbitMQ
        UserCreatedEvent event = UserCreatedEvent.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .build();

        rabbitTemplate.convertAndSend("user.exchange", "", event);

        UserDetails userDetails = jpaUserDetailsService.loadUserByUsername(user.getUsername());
        String token = jwtUtils.generateToken(userDetails);

        return new AuthenticationResult(
                "User " + userDetails.getUsername() + " is successfully registered",
                token
        );
    }

    /**
     * Handles user login
     */
    @Transactional(readOnly = true)
    public AuthenticationResult login(LoginRequest req) {
        UserDetails userDetails = jpaUserDetailsService.loadUserByUsername(req.username());

        if (!encoder.matches(req.password(), userDetails.getPassword())) {
            throw new IllegalArgumentException("Invalid password");
        }

        String token = jwtUtils.generateToken(userDetails);

        return new AuthenticationResult("Login successfully", token);
    }
}

