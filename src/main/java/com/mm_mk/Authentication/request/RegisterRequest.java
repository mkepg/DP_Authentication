package com.mm_mk.Authentication.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(

        @Schema(example = "john_doe", minLength = 4, maxLength = 50)
        @NotBlank(message = "Username is required")
        @Size(min = 4, max = 50, message = "Username must be between 4 and 50 characters")
        String username,

        @Schema(example = "securePassword123", minLength = 6)
        @NotBlank(message = "Password is required")
        @Size(min = 6, message = "Password must be at least 6 characters long")
        String password,

        @Schema(example = "john@example.com")
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        String email
) { }
