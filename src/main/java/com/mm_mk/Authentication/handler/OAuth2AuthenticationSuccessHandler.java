package com.mm_mk.Authentication.handler;

import com.mm_mk.Authentication.config.AppProperties;
import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
import com.mm_mk.Authentication.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AppProperties appProperties;
    private final UserRepository userRepository;
    private final UserService userService;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        HttpSession session = request.getSession(false);

        // Check if this is part of an OAuth2 authorization flow
        if (session != null && session.getAttribute("authRequest_clientId") != null) {
            handleAuthorizationCodeFlow(request, response, authentication, session);
        } else {
            // Fallback to direct redirect (legacy behavior)
            String targetUrl = determineTargetUrl(request, authentication);
            if (!response.isCommitted()) {
                clearAuthenticationAttributes(request);
                getRedirectStrategy().sendRedirect(request, response, targetUrl);
            }
        }
    }

    private void handleAuthorizationCodeFlow(HttpServletRequest request,
                                             HttpServletResponse response,
                                             Authentication authentication,
                                             HttpSession session) throws IOException {
        try {
            OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
            User user = createOrUpdateLocalUser(oauthUser);

            // Retrieve authorization request parameters
            String clientId = (String) session.getAttribute("authRequest_clientId");
            String redirectUri = (String) session.getAttribute("authRequest_redirectUri");
            String state = (String) session.getAttribute("authRequest_state");
            String codeChallenge = (String) session.getAttribute("authRequest_codeChallenge");
            String codeChallengeMethod = (String) session.getAttribute("authRequest_codeChallengeMethod");
            String scope = (String) session.getAttribute("authRequest_scope");

            // Clear session
            session.removeAttribute("authRequest_clientId");
            session.removeAttribute("authRequest_redirectUri");
            session.removeAttribute("authRequest_responseType");
            session.removeAttribute("authRequest_scope");
            session.removeAttribute("authRequest_state");
            session.removeAttribute("authRequest_codeChallenge");
            session.removeAttribute("authRequest_codeChallengeMethod");

            RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
            if (registeredClient == null) {
                throw new IllegalArgumentException("Invalid client_id");
            }

            // Validate redirect URI
            if (!registeredClient.getRedirectUris().contains(redirectUri)) {
                throw new IllegalArgumentException("Invalid redirect_uri: " + redirectUri);
            }

            // Generate authorization code
            String authorizationCodeValue = generateAuthorizationCode();
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plus(5, ChronoUnit.MINUTES);

            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    authorizationCodeValue, issuedAt, expiresAt
            );

            // Build authorization
            OAuth2Authorization.Builder authBuilder = OAuth2Authorization
                    .withRegisteredClient(registeredClient)
                    .principalName(user.getEmail())
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .attribute(OAuth2ParameterNames.STATE, state)
                    .attribute(OAuth2ParameterNames.SCOPE, scope);

            if (codeChallenge != null) {
                authBuilder
                        .attribute("code_challenge", codeChallenge)
                        .attribute("code_challenge_method", codeChallengeMethod != null ? codeChallengeMethod : "plain");
            }

            OAuth2Authorization authorization = authBuilder
                    .token(authorizationCode)
                    .attribute("user_id", user.getId().toString())
                    .attribute("user_email", user.getEmail())
                    .build();

            authorizationService.save(authorization);

            log.info("Generated authorization code for OAuth2 user: {}", user.getEmail());

            // Redirect with code
            UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(redirectUri)
                    .queryParam(OAuth2ParameterNames.CODE, authorizationCodeValue);

            if (state != null) {
                uriBuilder.queryParam(OAuth2ParameterNames.STATE, state);
            }

            clearAuthenticationAttributes(request);
            getRedirectStrategy().sendRedirect(request, response, uriBuilder.build().toUriString());

        } catch (Exception e) {
            log.error("OAuth2 authorization code flow failed", e);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Authorization failed");
        }
    }

    protected String determineTargetUrl(HttpServletRequest request, Authentication authentication) {
        // Legacy direct redirect - kept for backward compatibility
        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
        User user = createOrUpdateLocalUser(oauthUser);

        String redirectUriParam = request.getParameter("redirect_uri");
        String redirectUri = (redirectUriParam != null)
                ? redirectUriParam
                : appProperties.getDefaultRedirectUri();

        if (!appProperties.getAuthorizedRedirectUris().contains(redirectUri)) {
            throw new IllegalArgumentException("Unauthorized Redirect URI: " + redirectUri);
        }

        return UriComponentsBuilder.fromUriString(redirectUri)
                .fragment("user_id=" + user.getId())
                .build()
                .toUriString();
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
                        ""
                ));
    }

    private String generateAuthorizationCode() {
        byte[] randomBytes = new byte[32];
        new java.security.SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}