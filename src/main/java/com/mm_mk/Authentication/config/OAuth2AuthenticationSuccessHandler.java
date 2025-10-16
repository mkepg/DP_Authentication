package com.mm_mk.Authentication.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
import com.mm_mk.Authentication.response.UserDTO;
import com.mm_mk.Authentication.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtEncoder jwtEncoder;
    private final OAuth2AuthorizationService authorizationService;
    private final RegisteredClientRepository registeredClientRepository;
    private final AppProperties appProperties;
    private final UserRepository userRepository;
    private final UserService userService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        String targetUrl = determineTargetUrl(request, authentication);

        if (!response.isCommitted()) {
            getRedirectStrategy().sendRedirect(request, response, targetUrl);
        }
    }

    protected String determineTargetUrl(HttpServletRequest request, Authentication authentication) {
        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
        User user = createOrUpdateLocalUser(oauthUser);

        // Retrieve registered client
        RegisteredClient registeredClient = registeredClientRepository.findByClientId("internal-client");
        if (registeredClient == null) {
            throw new IllegalStateException("Registered client 'internal-client' not configured");
        }

        // Build JWT claims
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(2, ChronoUnit.HOURS);
        Set<String> scopes = Set.of("read", "write");

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("http://localhost:8080")
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .subject(user.getEmail())
                .claim("username", user.getUsername())
                .claim("scope", String.join(" ", scopes))
                .id(UUID.randomUUID().toString())
                .build();

        // Encode JWT using SAS encoder (PEM-based keypair)
        Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims));

        // Wrap as OAuth2 access token and store authorization
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                jwt.getTokenValue(),
                issuedAt,
                expiresAt,
                scopes
        );

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(user.getEmail())
                .authorizationGrantType(new org.springframework.security.oauth2.core.AuthorizationGrantType("oauth2_login"))
                .attribute(Authentication.class.getName(), authentication)
                .token(accessToken, metadata ->
                        metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwt.getClaims()))
                .build();

        authorizationService.save(authorization);

        // Build redirect URI
        String redirectUriParam = request.getParameter("redirect_uri");
        String redirectUri = (redirectUriParam != null)
                ? redirectUriParam
                : appProperties.getDefaultRedirectUri();

        if (!appProperties.getAuthorizedRedirectUris().contains(redirectUri)) {
            throw new IllegalArgumentException("Unauthorized Redirect URI: " + redirectUri);
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            UserDTO userDTO = new UserDTO(
                    user.getUsername(),
                    user.getEmail(),
                    user.getPreferredKeyboard()
            );
            String userJson = mapper.writeValueAsString(userDTO);
            String encodedUser = URLEncoder.encode(userJson, StandardCharsets.UTF_8);

            return UriComponentsBuilder.fromUriString(redirectUri)
                    .fragment("token=" + jwt.getTokenValue() + "&user=" + encodedUser)
                    .build()
                    .toUriString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize user", e);
        }
    }

    private User createOrUpdateLocalUser(OAuth2User oauthUser) {
        String email = (String) oauthUser.getAttributes().get("email");
        String name = (String) oauthUser.getAttributes().get("name");

        return userRepository.findByEmail(email)
                .map(existingUser -> {
                    existingUser.setUsername(name);
                    return userRepository.save(existingUser);
                })
                .orElseGet(() -> userService.createUser(
                        name != null ? name : email,
                        email,
                        "" // no password for OAuth
                ));
    }
}




//package com.mm_mk.Authentication.config;
//
//import com.fasterxml.jackson.databind.ObjectMapper;
//import com.mm_mk.Authentication.model.User;
//import com.mm_mk.Authentication.repository.UserRepository;
//import com.mm_mk.Authentication.response.UserDTO;
//import com.mm_mk.Authentication.service.UserService;
//import com.mm_mk.Authentication.util.JwtUtils;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.AllArgsConstructor;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.oauth2.core.user.OAuth2User;
//import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
//import org.springframework.stereotype.Component;
//import org.springframework.web.util.UriComponentsBuilder;
//
//import java.io.IOException;
//import java.net.URLEncoder;
//import java.nio.charset.StandardCharsets;
//import java.util.List;
//
//@Component
//@AllArgsConstructor
//public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
//
//    private final JwtUtils jwtUtils;
//    private final AppProperties appProperties;
//    private final UserRepository userRepository;
//    private final UserService userService;
//
//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request,
//                                        HttpServletResponse response,
//                                        Authentication authentication) throws IOException {
//        String targetUrl = determineTargetUrl(request, authentication);
//
//        if (response.isCommitted()) {
//            return;
//        }
//        getRedirectStrategy().sendRedirect(request, response, targetUrl);
//    }
//
//    protected String determineTargetUrl(HttpServletRequest request, Authentication authentication) {
//
//        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
//        User user = createOrUpdateLocalUser(oauthUser);
//
//        // Wrap local User into Spring Security UserDetails for JWT
//        org.springframework.security.core.userdetails.User springUser =
//                new org.springframework.security.core.userdetails.User(
//                        user.getEmail(),
//                        user.getPasswordHash() != null ? user.getPasswordHash() : "",
//                        List.of(new SimpleGrantedAuthority("ROLE_USER"))
//                );
//
//        String jwt = jwtUtils.generateToken(springUser);
//
//        // Handle redirect param vs default
//        String redirectUriParam = request.getParameter("redirect_uri");
//        String redirectUri = (redirectUriParam != null)
//                ? redirectUriParam
//                : appProperties.getDefaultRedirectUri();
//
//        if (!appProperties.getAuthorizedRedirectUris().contains(redirectUri)) {
//            throw new IllegalArgumentException("Unauthorized Redirect URI: " + redirectUri);
//        }
//
//        try {
//            ObjectMapper mapper = new ObjectMapper();
//
//            UserDTO userDTO = new UserDTO(
//                    user.getUsername(),
//                    user.getEmail(),
//                    user.getPreferredKeyboard()
//            );
//
//            String userJson = mapper.writeValueAsString(userDTO);
//            String encodedUser = URLEncoder.encode(userJson, StandardCharsets.UTF_8);
//
//            return UriComponentsBuilder.fromUriString(redirectUri)
//                    .fragment("token=" + jwt + "&user=" + encodedUser)
//                    .build()
//                    .toUriString();
//        } catch (Exception e) {
//            throw new RuntimeException("Failed to serialize user", e);
//        }
//    }
//
//    private User createOrUpdateLocalUser(OAuth2User oauthUser) {
//        String email = (String) oauthUser.getAttributes().get("email");
//        String name = (String) oauthUser.getAttributes().get("name");
//
//        return userRepository.findByEmail(email)
//                .map(existingUser -> {
//                    existingUser.setUsername(name);
//                    return userRepository.save(existingUser);
//                })
//                .orElseGet(() -> userService.createUser(
//                        name != null ? name : email,
//                        email,
//                        "" // no password for OAuth
//                ));
//    }
//}
