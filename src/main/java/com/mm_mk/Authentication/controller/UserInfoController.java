package com.mm_mk.Authentication.controller;

import com.mm_mk.Authentication.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class UserInfoController {

    private final UserRepository userRepository;

    @GetMapping("/userinfo")
    public Map<String, Object> userInfo(Authentication authentication) {
        Map<String, Object> userInfo = new HashMap<>();

        if (authentication.getPrincipal() instanceof Jwt jwt) {
            String username = jwt.getSubject();

            userRepository.findByUsername(username).ifPresent(user -> {
                userInfo.put("sub", user.getUsername());
                userInfo.put("user_id", user.getId().toString());
                userInfo.put("email", user.getEmail());
                userInfo.put("preferred_username", user.getUsername());
                userInfo.put("preferred_keyboard", user.getPreferredKeyboard().name());
            });
        }

        return userInfo;
    }
}