package com.mm_mk.Authentication.oauth2;

import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
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

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class PasswordPkceGrantAuthenticationProvider implements AuthenticationProvider {
    private static final Logger logger = LoggerFactory.getLogger(PasswordPkceGrantAuthenticationProvider.class);
    private final OAuth2AuthorizationService authorizationService;
    private final UserRepository userRepository;
    private final ObjectProvider<AuthenticationManager> authenticationManagerProvider;
    private final JwtEncoder jwtEncoder;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    @Value("${app.oauth2.issuer:http://localhost:8080}")
    private String issuer;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PasswordPkceGrantAuthenticationToken passwordPkceAuthentication = (PasswordPkceGrantAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = (OAuth2ClientAuthenticationToken) passwordPkceAuthentication.getPrincipal();
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        logger.info("🔐 DEBUG - Starting authentication");
        logger.info("🔐 DEBUG - tokenGenerator: {}", tokenGenerator != null ? "present" : "NULL");
        logger.info("🔐 DEBUG - jwtEncoder: {}", jwtEncoder != null ? "present" : "NULL");
        logger.info("🔐 DEBUG - registeredClient: {}", registeredClient != null ? "present" : "NULL");

        Authentication userAuthentication = authenticationManagerProvider.getObject().authenticate(
            new UsernamePasswordAuthenticationToken(
                passwordPkceAuthentication.getUsername(),
                passwordPkceAuthentication.getPassword()
            )
        );

        String canonicalUsername = userAuthentication.getName();
        User user = userRepository.findByUsername(canonicalUsername)
            .orElseThrow(() -> new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT));

        logger.info("🔐 DEBUG - User authenticated: {}", user.getUsername());
        logger.info("🔐 DEBUG - userAuthentication: {}", userAuthentication != null ? "present" : "NULL");
        logger.info("🔐 DEBUG - Attempting manual JWT creation...");

        Jwt jwt = createSimpleJwt(user, registeredClient);

        logger.info("🔐 DEBUG - Manual JWT created successfully");

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            jwt.getTokenValue(),
            jwt.getIssuedAt(),
            jwt.getExpiresAt(),
            registeredClient.getScopes()
        );

        logger.info("🔐 DEBUG - Access token created");

        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
            "refresh_" + System.currentTimeMillis(),
            Instant.now(),
            Instant.now().plusSeconds(86400)
        );

        logger.info("🔐 DEBUG - Refresh token created");

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName(user.getId().toString())
            .authorizationGrantType(new AuthorizationGrantType("password_pkce"))
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .build();

        logger.info("🔐 DEBUG - Authorization built, attempting save...");
        authorizationService.save(authorization);
        logger.info("🔐 DEBUG - Authorization saved successfully");

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("user_id", user.getId().toString());
        additionalParameters.put("preferred_keyboard", user.getPreferredKeyboard().name());

        logger.info("🔐 DEBUG - Returning successful authentication");

        return new OAuth2AccessTokenAuthenticationToken(
            registeredClient,
            clientPrincipal,
            accessToken,
            refreshToken,
            additionalParameters
        );
    }

    private Jwt createSimpleJwt(User user, RegisteredClient registeredClient) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
            .issuer(issuer)
            .subject(user.getId().toString())
            .audience(List.of(registeredClient.getClientId()))
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(7200))
            .claim("username", user.getUsername())
            .claim("email", user.getEmail())
            .claim("preferred_keyboard", user.getPreferredKeyboard().name())
            .build();
        return jwtEncoder.encode(JwtEncoderParameters.from(claims));
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
