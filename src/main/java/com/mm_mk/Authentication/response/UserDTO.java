package com.mm_mk.Authentication.response;

import com.mm_mk.Authentication.model.KeyboardModel;

public record UserDTO(
        String username,
        String email,
        KeyboardModel preferredKeyboard
) {}