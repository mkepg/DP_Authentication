package com.mm_mk.Authentication.controller;

import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
import com.mm_mk.Authentication.service.UserService;
import com.mm_mk.Authentication.util.CorrelationIdUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.time.Instant;
import java.util.UUID;
import java.util.List;

@Controller
@RequiredArgsConstructor
@Tag(name = "OAuth2", description = "OAuth2 authentication flow")
public class OAuthSuccessController {

    private static final Logger logger = LoggerFactory.getLogger(OAuthSuccessController.class);
    private static final long SLOW_OPERATION_THRESHOLD_MS = 1000;

    private final UserRepository userRepository;
    private final UserService userService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final RegisteredClientRepository registeredClientRepository;
    private final JwtEncoder jwtEncoder;

    @GetMapping("/oauth-success")
    @Operation(summary = "OAuth2 success callback", description = "Handles OAuth2 login success")
    @ApiResponse(responseCode = "200", description = "OAuth login successful")
    public String oauthSuccess(@AuthenticationPrincipal OAuth2User oauth2User, HttpServletRequest request, Model model) {
        long startTime = System.currentTimeMillis();
        String correlationId = CorrelationIdUtil.getCorrelationId();
        logger.info("Processing OAuth success - correlationId: {}, user: {}", correlationId, oauth2User.getName());

        try {
            String name = oauth2User.getAttribute("name");
            String email = oauth2User.getAttribute("email");
            if (email == null) {
                logger.error("Email not found from OAuth2 provider - correlationId: {}, user: {}", correlationId, oauth2User.getName());
                throw new IllegalStateException("Email not found from OAuth2 provider");
            }

            User user = userRepository.findByEmail(email)
                    .map(existingUser -> {
                        if (name != null && !name.equals(existingUser.getUsername())) {
                            logger.debug("Updating username for user - correlationId: {}, email: {}, from: {} to: {}", correlationId, email, existingUser.getUsername(), name);
                            existingUser.setUsername(name);
                            return userRepository.save(existingUser);
                        }
                        logger.debug("User already exists, no update needed - correlationId: {}, email: {}", correlationId, email);
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
                        logger.info("Creating new user from OAuth - correlationId: {}, username: {}, email: {}", correlationId, uniqueUsername, email);
                        return userService.createUser(uniqueUsername, email, randomPassword);
                    });

            String accessToken = generateAccessToken(user);
            if (accessToken == null) {
                logger.error("Failed to generate access token - correlationId: {}, user: {}", correlationId, user.getUsername());
                throw new IllegalStateException("Failed to generate access token");
            }

            model.addAttribute("userId", user.getId().toString());
            model.addAttribute("username", user.getUsername());
            model.addAttribute("email", user.getEmail());
            model.addAttribute("preferredKeyboard", user.getPreferredKeyboard().name());
            model.addAttribute("accessToken", accessToken);

            logger.info("OAuth success processed - correlationId: {}, user: {}, userId: {}", correlationId, user.getUsername(), user.getId());
            return "oauth-success";

        } catch (Exception e) {
            logger.error("OAuth success processing failed - correlationId: {}", correlationId, e);
            model.addAttribute("error", e.getMessage());
            return "oauth-error";
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            logger.debug("OAuth success processing completed in {}ms - correlationId: {}", duration, correlationId);
            if (duration > SLOW_OPERATION_THRESHOLD_MS)
                logger.warn("SLOW OPERATION: OAuth success processing took {}ms - correlationId: {}", duration, correlationId);
        }
    }

    private String generateAccessToken(User user) {
        long startTime = System.currentTimeMillis();
        String correlationId = CorrelationIdUtil.getCorrelationId();
        logger.debug("Generating access token - correlationId: {}, user: {}", correlationId, user.getUsername());

        try {
            RegisteredClient registeredClient = registeredClientRepository.findByClientId("internal-client");
            if (registeredClient == null) {
                logger.error("Registered client not found - correlationId: {}, clientId: internal-client", correlationId);
                return null;
            }

            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuer("http://localhost:8080")
                    .subject(user.getId().toString())
                    .audience(List.of(registeredClient.getClientId()))
                    .issuedAt(Instant.now())
                    .expiresAt(Instant.now().plusSeconds(7200))
                    .claim("username", user.getUsername())
                    .claim("email", user.getEmail())
                    .claim("preferred_keyboard", user.getPreferredKeyboard().name())
                    .build();

            Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims));

            logger.debug("JWT token generated successfully - correlationId: {}, user: {}, subject (UUID): {}", correlationId, user.getUsername(), user.getId());
            return jwt.getTokenValue();

        } catch (Exception e) {
            logger.error("Token generation failed - correlationId: {}, user: {}", correlationId, user.getUsername(), e);
            return null;
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            logger.debug("Token generation completed in {}ms - correlationId: {}", duration, correlationId);
            if (duration > SLOW_OPERATION_THRESHOLD_MS)
                logger.warn("SLOW OPERATION: Token generation took {}ms - correlationId: {}", duration, correlationId);
        }
    }
}
