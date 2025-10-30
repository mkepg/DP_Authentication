package com.mm_mk.Authentication.request;

import com.mm_mk.Authentication.model.KeyboardModel;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Size;

public record UpdateUserRequest(
        @Schema(example = "john_doe_updated")
        @Size(min = 4, max = 50, message = "Username must be between 4 and 50 characters")
        String username,

        @Schema(
                example = "Midiplus",
                allowableValues = {"Casio", "Midiplus"}
        )
        KeyboardModel preferredKeyboard
) { }