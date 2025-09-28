package com.mm_mk.DP.Authentication.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TokenResponse {
    private String message;
    private String token;
}
