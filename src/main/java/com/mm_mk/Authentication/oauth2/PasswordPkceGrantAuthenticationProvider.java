package com.mm_mk.Authentication.oauth2;

import com.mm_mk.Authentication.repository.UserRepository;
import com.mm_mk.Authentication.model.User;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class PasswordPkceGrantAuthenticationProvider implements AuthenticationProvider {
    private static final Logger log = LoggerFactory.getLogger(PasswordPkceGrantAuthenticationProvider.class);
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final UserRepository userRepository;
    private final ObjectProvider<AuthenticationManager> authenticationManagerProvider;

    @Override
    public boolean supports(Class<?> authentication) {
        boolean supports = PasswordPkceGrantAuthenticationToken.class.isAssignableFrom(authentication);
        log.debug("Supports authentication type {}: {}", authentication, supports);
        return supports;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.info("=== PasswordPkceGrantAuthenticationProvider.authenticate() ===");

        PasswordPkceGrantAuthenticationToken passwordPkceAuthentication =
                (PasswordPkceGrantAuthenticationToken) authentication;

        Object principal = passwordPkceAuthentication.getPrincipal();
        log.info("Principal type: {}", principal.getClass().getName());

        if (!(principal instanceof OAuth2ClientAuthenticationToken)) {
            log.error("Principal is not OAuth2ClientAuthenticationToken: {}", principal);
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        OAuth2ClientAuthenticationToken clientPrincipal = (OAuth2ClientAuthenticationToken) principal;
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        log.info("Client ID: {}", registeredClient.getClientId());
        log.info("Client requires PKCE: {}", registeredClient.getClientSettings().isRequireProofKey());

        if (!registeredClient.getClientSettings().isRequireProofKey()) {
            log.error("Client does not require PKCE but it's required for this grant type");
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        AuthenticationManager authenticationManager = authenticationManagerProvider.getObject();
        log.info("AuthenticationManager obtained: {}", authenticationManager != null);

        log.info("Attempting to authenticate user: {}", passwordPkceAuthentication.getUsername());
        Authentication userAuthentication;
        try {
            userAuthentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            passwordPkceAuthentication.getUsername(),
                            passwordPkceAuthentication.getPassword()
                    )
            );
            log.info("User authentication successful: {}", userAuthentication.isAuthenticated());
        } catch (AuthenticationException e) {
            log.error("User authentication failed for {}: {}", passwordPkceAuthentication.getUsername(), e.getMessage());
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        User user = userRepository.findByUsername(passwordPkceAuthentication.getUsername())
                .orElseThrow(() -> {
                    log.error("User not found in database: {}", passwordPkceAuthentication.getUsername());
                    return new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
                });
        log.info("User found: {} ({})", user.getUsername(), user.getId());

        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(userAuthentication)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizedScopes(registeredClient.getScopes())
                .authorizationGrantType(new AuthorizationGrantType("password_pkce"))
                .authorizationGrant(passwordPkceAuthentication)
                .build();

        log.info("Generating token for scopes: {}", registeredClient.getScopes());

        OAuth2Token generatedToken = tokenGenerator.generate(tokenContext);
        if (generatedToken == null) {
            log.error("Token generator returned null");
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedToken.getTokenValue(),
                generatedToken.getIssuedAt(),
                generatedToken.getExpiresAt(),
                tokenContext.getAuthorizedScopes()
        );

        log.info("Access token generated, expires at: {}", accessToken.getExpiresAt());

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(userAuthentication.getName())
                .authorizationGrantType(new AuthorizationGrantType("password_pkce"))
                .attribute(Principal.class.getName(), userAuthentication)
                .attribute("code_challenge", passwordPkceAuthentication.getCodeChallenge())
                .attribute("code_challenge_method", passwordPkceAuthentication.getCodeChallengeMethod())
                .accessToken(accessToken)
                .build();

        authorizationService.save(authorization);
        log.info("Authorization saved for user: {}", userAuthentication.getName());

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("user_id", user.getId().toString());
        additionalParameters.put("preferred_keyboard", user.getPreferredKeyboard().name());

        log.info("Returning OAuth2AccessTokenAuthenticationToken with additional parameters: {}", additionalParameters);
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, null, additionalParameters);
    }
}