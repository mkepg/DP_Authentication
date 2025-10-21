package com.mm_mk.Authentication.request;

import com.mm_mk.Authentication.model.KeyboardModel;
import jakarta.validation.constraints.Size;

public record UpdateUserRequest(
        @Size(min = 4, max = 50, message = "Username must be between 4 and 50 characters")
        String username,

        KeyboardModel preferredKeyboard
) { }