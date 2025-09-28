package com.mm_mk.DP.Authentication.controller;

import com.mm_mk.DP.Authentication.model.User;
import com.mm_mk.DP.Authentication.repository.UserRepository;
import com.mm_mk.DP.Authentication.request.LoginRequest;
import com.mm_mk.DP.Authentication.request.RegisterRequest;
import com.mm_mk.DP.Authentication.response.AuthenticationResult;
import com.mm_mk.DP.Authentication.security.JpaUserDetailsService;
import com.mm_mk.DP.Authentication.security.JwtUtils;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
public class AuthController {
    private final UserRepository repo;
    private final PasswordEncoder encoder;
    private final JpaUserDetailsService jpaUserDetailsService;
    private final JwtUtils jwtUtils;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResult> register(@Valid @RequestBody RegisterRequest req) {
        if (repo.existsByUsername(req.username())) {
            throw new IllegalArgumentException("Username already exists");
        }

        User u = User.builder()
                .username(req.username())
                .passwordHash(encoder.encode(req.password()))
                .email(req.email())
                .build();
        repo.save(u);

        UserDetails user = jpaUserDetailsService.loadUserByUsername(u.getUsername());
        String token = jwtUtils.generateToken(user);

        AuthenticationResult authenticationResult = new AuthenticationResult(
                "User " + user.getUsername() + " is successfully registered",
                token
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(authenticationResult);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResult> login(@Valid @RequestBody LoginRequest req) {
        UserDetails user = jpaUserDetailsService.loadUserByUsername(req.username());

        if (!encoder.matches(req.password(), user.getPassword())) {
            throw new IllegalArgumentException("Invalid password");
        }

        String token = jwtUtils.generateToken(user);
        AuthenticationResult authenticationResult = new AuthenticationResult("Login successfully", token);

        return ResponseEntity.ok(authenticationResult);
    }
}
