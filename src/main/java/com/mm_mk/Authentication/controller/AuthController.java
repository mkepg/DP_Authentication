package com.mm_mk.Authentication.controller;

import com.mm_mk.Authentication.request.LoginRequest;
import com.mm_mk.Authentication.request.RegisterRequest;
import com.mm_mk.Authentication.request.UpdateUserRequest;
import com.mm_mk.Authentication.response.AuthenticationResult;
import com.mm_mk.Authentication.response.UserDTO;
import com.mm_mk.Authentication.service.AuthService;
import com.mm_mk.Authentication.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResult> register(@Valid @RequestBody RegisterRequest req) {
        AuthenticationResult result = authService.register(req);
        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    @PutMapping("/{userId}")
    public ResponseEntity<UserDTO> updateUser(
            @PathVariable UUID userId,
            @Valid @RequestBody UpdateUserRequest updateRequest,
            Authentication authentication) {

        UserDTO userDTO = authService.update(userId, updateRequest, authentication);
        return ResponseEntity.ok(userDTO);
    }

}
