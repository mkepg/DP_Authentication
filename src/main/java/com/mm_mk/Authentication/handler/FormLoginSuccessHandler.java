package com.mm_mk.Authentication.handler;

import com.mm_mk.Authentication.config.AppProperties;
import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
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
@Component("formLoginSuccessHandler")
@RequiredArgsConstructor
public class FormLoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final AppProperties appProperties;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        HttpSession session = request.getSession(false);

        // Check if this is part of an OAuth2 authorization flow
        if (session != null && session.getAttribute("authRequest_clientId") != null) {
            handleAuthorizationCodeFlow(request, response, authentication, session);
        } else {
            // No OAuth2 flow detected - redirect to default frontend
            log.warn("Form login completed but no OAuth2 authorization request found in session. Redirecting to default URI.");
            String defaultRedirect = appProperties.getDefaultRedirectUri();
            getRedirectStrategy().sendRedirect(request, response, defaultRedirect);
        }
    }

    private void handleAuthorizationCodeFlow(HttpServletRequest request,
                                             HttpServletResponse response,
                                             Authentication authentication,
                                             HttpSession session) throws IOException {
        try {
            // Retrieve authorization request parameters from session
            String clientId = (String) session.getAttribute("authRequest_clientId");
            String redirectUri = (String) session.getAttribute("authRequest_redirectUri");
            String state = (String) session.getAttribute("authRequest_state");
            String codeChallenge = (String) session.getAttribute("authRequest_codeChallenge");
            String codeChallengeMethod = (String) session.getAttribute("authRequest_codeChallengeMethod");
            String scope = (String) session.getAttribute("authRequest_scope");

            log.info("Processing authorization code flow for client: {}", clientId);
            log.info("Redirect URI: {}", redirectUri);
            log.info("Code Challenge present: {}", codeChallenge != null);

            // Clear session attributes
            session.removeAttribute("authRequest_clientId");
            session.removeAttribute("authRequest_redirectUri");
            session.removeAttribute("authRequest_responseType");
            session.removeAttribute("authRequest_scope");
            session.removeAttribute("authRequest_state");
            session.removeAttribute("authRequest_codeChallenge");
            session.removeAttribute("authRequest_codeChallengeMethod");

            // Validate client
            RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
            if (registeredClient == null) {
                log.error("Invalid client_id: {}", clientId);
                throw new IllegalArgumentException("Invalid client_id: " + clientId);
            }

            // Validate redirect URI
            if (!registeredClient.getRedirectUris().contains(redirectUri)) {
                log.error("Invalid redirect_uri: {}. Registered URIs: {}", redirectUri, registeredClient.getRedirectUris());
                throw new IllegalArgumentException("Invalid redirect_uri: " + redirectUri);
            }

            // Get user from database
            String username = authentication.getName();
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new IllegalStateException("User not found: " + username));

            // Generate authorization code
            String authorizationCodeValue = generateAuthorizationCode();
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plus(5, ChronoUnit.MINUTES);

            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    authorizationCodeValue,
                    issuedAt,
                    expiresAt
            );

            // Build OAuth2Authorization
            OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                    .withRegisteredClient(registeredClient)
                    .principalName(username)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .attribute(OAuth2ParameterNames.STATE, state)
                    .attribute(OAuth2ParameterNames.SCOPE, scope);

            // Store PKCE challenge if present
            if (codeChallenge != null) {
                authorizationBuilder
                        .attribute("code_challenge", codeChallenge)
                        .attribute("code_challenge_method", codeChallengeMethod != null ? codeChallengeMethod : "plain");
                log.info("PKCE challenge stored for authorization code");
            }

            OAuth2Authorization authorization = authorizationBuilder
                    .token(authorizationCode)
                    .attribute("user_id", user.getId().toString())
                    .attribute("user_email", user.getEmail())
                    .build();

            // Save authorization
            authorizationService.save(authorization);

            log.info("Generated authorization code for user: {}, code: {}", username, authorizationCodeValue.substring(0, 10) + "...");

            // Build redirect URL with authorization code
            UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(redirectUri)
                    .queryParam(OAuth2ParameterNames.CODE, authorizationCodeValue);

            if (state != null) {
                uriBuilder.queryParam(OAuth2ParameterNames.STATE, state);
            }

            String targetUrl = uriBuilder.build().toUriString();
            log.info("Redirecting to: {}", targetUrl);

            clearAuthenticationAttributes(request);
            getRedirectStrategy().sendRedirect(request, response, targetUrl);

        } catch (Exception e) {
            log.error("Error in authorization code flow", e);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Authorization failed: " + e.getMessage());
        }
    }

    private String generateAuthorizationCode() {
        byte[] randomBytes = new byte[32];
        new java.security.SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}