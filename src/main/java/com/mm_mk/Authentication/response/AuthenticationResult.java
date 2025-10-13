package com.mm_mk.Authentication.response;

import com.mm_mk.Authentication.model.User;

public record AuthenticationResult(
        String message,
        String token,
        User user
) { }
