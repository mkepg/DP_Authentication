package com.mm_mk.Authentication.service;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // Delegate to the default implementation to fetch user info from provider
        OAuth2User oauth2User = delegate.loadUser(userRequest);

        // Extract user attributes from provider
        Map<String, Object> attributes = new HashMap<>(oauth2User.getAttributes());

        if (!attributes.containsKey("email")) {
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider");
        }

        return oauth2User;
    }
}
