package com.mm_mk.Authentication.service;

import com.mm_mk.Authentication.repository.UserRepository;
import com.mm_mk.Authentication.response.AuthenticationResult;
import com.mm_mk.Authentication.response.UserDTO;
import com.mm_mk.Authentication.util.JwtUtils;
import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.request.LoginRequest;
import com.mm_mk.Authentication.request.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository repo;
    private final UserService userService;
    private final PasswordEncoder encoder;
    private final JpaUserDetailsService jpaUserDetailsService;
    private final JwtUtils jwtUtils;
    private final RabbitTemplate rabbitTemplate;

    @Transactional
    public AuthenticationResult register(RegisterRequest req) {
        if (repo.existsByUsername(req.username())) {
            throw new IllegalArgumentException("Username already exists");
        }

        User user = userService.createUser(
                req.username(),
                req.email(),
                encoder.encode(req.password())
        );

        UserDetails userDetails = jpaUserDetailsService.loadUserByUsername(user.getUsername());
        String token = jwtUtils.generateToken(userDetails);

        UserDTO userDTO = new UserDTO(
                user.getUsername(),
                user.getEmail(),
                user.getPreferredKeyboard()
        );

        return new AuthenticationResult("User " + userDetails.getUsername() + " is successfully registered", token, userDTO);
    }

    @Transactional(readOnly = true)
    public AuthenticationResult login(LoginRequest req) {
        if ((req.username() == null || req.username().isBlank()) &&
                (req.email() == null || req.email().isBlank())) {
            throw new IllegalArgumentException("Username or email must be provided");
        }

        User user;
        UserDetails userDetails;

        if (req.username() != null && !req.username().isBlank()) {
            user = repo.findByUsername(req.username())
                    .orElseThrow(() -> new UsernameNotFoundException("No user with username: " + req.username()));
            userDetails = jpaUserDetailsService.loadUserByUsername(req.username());
        } else {
            user = repo.findByEmail(req.email())
                    .orElseThrow(() -> new UsernameNotFoundException("No user with email: " + req.email()));
            userDetails = jpaUserDetailsService.loadUserByEmail(req.email());
        }

        if (!encoder.matches(req.password(), userDetails.getPassword()))
            throw new IllegalArgumentException("Invalid password");

        String token = jwtUtils.generateToken(userDetails);

        UserDTO userDTO = new UserDTO(
                user.getUsername(),
                user.getEmail(),
                user.getPreferredKeyboard()
        );

        return new AuthenticationResult("Login successfully", token, userDTO);
    }

}

