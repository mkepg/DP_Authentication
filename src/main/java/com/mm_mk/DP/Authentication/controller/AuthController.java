package com.mm_mk.DP.Authentication.controller;

import com.mm_mk.DP.Authentication.model.User;
import com.mm_mk.DP.Authentication.repository.UserRepository;
import com.mm_mk.DP.Authentication.request.LoginRequest;
import com.mm_mk.DP.Authentication.request.RegisterRequest;
import com.mm_mk.DP.Authentication.response.TokenResponse;
import com.mm_mk.DP.Authentication.security.JpaUserDetailsService;
import com.mm_mk.DP.Authentication.security.JwtUtils;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
public class AuthController {
    private final UserRepository repo;
    private final PasswordEncoder encoder;
    private final JpaUserDetailsService jpaUserDetailsService;
    private final JwtUtils jwtUtils;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req, BindingResult result) {

        if(result.hasErrors()) {
            return ResponseEntity.badRequest().body(
                    result.getAllErrors().stream()
                            .map(error -> error.getDefaultMessage())
                            .toList()
            );
        }

        if (repo.existsByUsername(req.getUsername())) {
            return ResponseEntity.badRequest().body("Username already exists");
        }

        User u = User.builder()
                .username(req.getUsername())
                .passwordHash(encoder.encode(req.getPassword()))
                .email(req.getEmail())
                .build();
        repo.save(u);

        return ResponseEntity.ok("User " + u.getUsername() + " is successfully registered");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req) {
        try {
            UserDetails user = jpaUserDetailsService.loadUserByUsername(req.getUsername());
            if (!encoder.matches(req.getPassword(), user.getPassword())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid password");
            }
            String token = jwtUtils.generateToken(user);
            TokenResponse tokenResponse = new TokenResponse("Login successfully", token);
            return ResponseEntity.ok(tokenResponse);
        } catch (UsernameNotFoundException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Username is not found");
        }
    }
}
