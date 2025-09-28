package com.mm_mk.DP.Authentication.response;

public record AuthenticationResult(
        String message,
        String token
) { }