package com.mm_mk.Authentication.response;

public record AuthenticationResult(
        String message,
        String token
) { }