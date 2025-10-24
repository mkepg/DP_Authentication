package com.mm_mk.Authentication.controller;

import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
import com.mm_mk.Authentication.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.UUID;
import java.util.List;

@Slf4j
@Controller
@RequiredArgsConstructor
public class OAuthSuccessController {

    private final UserRepository userRepository;
    private final UserService userService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final RegisteredClientRepository registeredClientRepository;

    @GetMapping("/oauth-success")
    public String oauthSuccess(@AuthenticationPrincipal OAuth2User oauth2User, HttpServletRequest request, Model model) {
        try {
            String name = oauth2User.getAttribute("name");
            String email = oauth2User.getAttribute("email");
            if (email == null)
                throw new IllegalStateException("Email not found from OAuth2 provider");

            User user = userRepository.findByEmail(email)
                    .map(existingUser -> {
                        if (name != null && !name.equals(existingUser.getUsername())) {
                            existingUser.setUsername(name);
                            return userRepository.save(existingUser);
                        }
                        return existingUser;
                    })
                    .orElseGet(() -> {
                        String username = name != null ? name : email.split("@")[0];
                        String uniqueUsername = username;
                        int counter = 1;
                        while (userRepository.findByUsername(uniqueUsername).isPresent()) {
                            uniqueUsername = username + counter;
                            counter++;
                        }
                        String randomPassword = UUID.randomUUID().toString();
                        return userService.createUser(uniqueUsername, email, randomPassword);
                    });

            String accessToken = generateAccessToken(user);
            if (accessToken == null)
                throw new IllegalStateException("Failed to generate access token");

            model.addAttribute("userId", user.getId().toString());
            model.addAttribute("username", user.getUsername());
            model.addAttribute("email", user.getEmail());
            model.addAttribute("preferredKeyboard", user.getPreferredKeyboard().name());
            model.addAttribute("accessToken", accessToken);

            log.info("OAuth success for user: {} with token generated", user.getUsername());
            return "oauth-success";

        } catch (Exception e) {
            log.error("OAuth success processing failed", e);
            model.addAttribute("error", e.getMessage());
            return "oauth-error";
        }
    }

    private String generateAccessToken(User user) {
        try {
            log.info("Generating access token for user: {}", user.getUsername());

            RegisteredClient registeredClient = registeredClientRepository.findByClientId("internal-client");
            if (registeredClient == null) {
                log.error("Registered client not found: internal-client");
                return null;
            }

            Authentication authentication = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                    user.getUsername(),
                    null,
                    List.of(new SimpleGrantedAuthority("ROLE_USER"))
            );

            OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                    .registeredClient(registeredClient)
                    .principal(authentication)
                    .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                    .authorizedScopes(registeredClient.getScopes())
                    .authorizationGrantType(new org.springframework.security.oauth2.core.AuthorizationGrantType("oauth_success"))
                    .build();

            log.info("Token context built, generating token...");

            OAuth2Token generatedToken = tokenGenerator.generate(tokenContext);

            if (generatedToken instanceof Jwt jwt) {
                log.info("JWT token generated successfully for user: {}", user.getUsername());
                return jwt.getTokenValue();
            } else if (generatedToken != null) {
                log.info("Non-JWT token generated, type: {}", generatedToken.getClass().getSimpleName());
                return generatedToken.getTokenValue();
            } else {
                log.error("Token generator returned null");
                return null;
            }

        } catch (Exception e) {
            log.error("Token generation failed for user: {}", user.getUsername(), e);
            return null;
        }
    }
}