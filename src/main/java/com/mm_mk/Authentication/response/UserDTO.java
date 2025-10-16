package com.mm_mk.Authentication.response;

import com.mm_mk.Authentication.model.KeyboardModel;

import java.util.UUID;

public record UserDTO(
        UUID id,

        String username,
        String email,
        KeyboardModel preferredKeyboard
) {}