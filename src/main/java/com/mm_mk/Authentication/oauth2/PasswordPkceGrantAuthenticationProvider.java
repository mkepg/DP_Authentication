package com.mm_mk.Authentication.oauth2;

import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
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

import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class PasswordPkceGrantAuthenticationProvider implements AuthenticationProvider {
    private static final Logger logger = LoggerFactory.getLogger(PasswordPkceGrantAuthenticationProvider.class);
    private final OAuth2AuthorizationService authorizationService;
    private final UserRepository userRepository;
    private final ObjectProvider<AuthenticationManager> authenticationManagerProvider;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PasswordPkceGrantAuthenticationToken passwordPkceAuthentication = (PasswordPkceGrantAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = (OAuth2ClientAuthenticationToken) passwordPkceAuthentication.getPrincipal();
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        Authentication userAuthentication = authenticationManagerProvider.getObject().authenticate(
            new UsernamePasswordAuthenticationToken(
                passwordPkceAuthentication.getUsername(),
                passwordPkceAuthentication.getPassword()
            )
        );

        String canonicalUsername = userAuthentication.getName();
        User user = userRepository.findByUsername(canonicalUsername)
            .orElseThrow(() -> new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT));

        logger.debug("password_pkce grant authenticated user: {}", user.getId());

        OAuth2Token generatedAccessToken = tokenGenerator.generate(
            createTokenContext(registeredClient, userAuthentication));
        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.SERVER_ERROR, "Failed to generate access token", null));
        }
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.getTokenValue(),
            generatedAccessToken.getIssuedAt(),
            generatedAccessToken.getExpiresAt(),
            registeredClient.getScopes()
        );

        OAuth2Token generatedRefreshToken = tokenGenerator.generate(
            createRefreshTokenContext(registeredClient, userAuthentication));
        if (!(generatedRefreshToken instanceof OAuth2RefreshToken refreshToken)) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.SERVER_ERROR, "Failed to generate refresh token", null));
        }

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName(canonicalUsername)
            .authorizationGrantType(new AuthorizationGrantType("password_pkce"))
            .authorizedScopes(registeredClient.getScopes())
            .attribute(java.security.Principal.class.getName(), userAuthentication)
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .build();

        authorizationService.save(authorization);

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("user_id", user.getId().toString());
        additionalParameters.put("preferred_keyboard", user.getPreferredKeyboard().name());

        return new OAuth2AccessTokenAuthenticationToken(
            registeredClient,
            clientPrincipal,
            accessToken,
            refreshToken,
            additionalParameters
        );
    }

    private OAuth2TokenContext createTokenContext(RegisteredClient registeredClient, Authentication userAuthentication) {
        return DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(userAuthentication)
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizedScopes(registeredClient.getScopes())
            .authorizationGrantType(new AuthorizationGrantType("password_pkce"))
            .build();
    }

    private OAuth2TokenContext createRefreshTokenContext(RegisteredClient registeredClient, Authentication userAuthentication) {
        return DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(userAuthentication)
            .tokenType(OAuth2TokenType.REFRESH_TOKEN)
            .authorizedScopes(registeredClient.getScopes())
            .authorizationGrantType(new AuthorizationGrantType("password_pkce"))
            .build();
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PasswordPkceGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
