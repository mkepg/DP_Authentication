package com.mm_mk.Authentication.config;

import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class AuthorizationServerBeansConfig {
    private final FrontendProperties frontendProperties;
    private final JwtProperties jwtProperties;
    private static final Logger logger = LoggerFactory.getLogger(AuthorizationServerBeansConfig.class);
    private final UserRepository userRepository;

    @Value("${app.oauth2.issuer:http://localhost:8080}")
    private String issuer;

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
            .issuer(issuer)
            .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient.Builder clientBuilder = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("internal-client")
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(new AuthorizationGrantType("password_pkce"))
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope(OidcScopes.EMAIL)
            .scope("read")
            .scope("write")
            .tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofSeconds(jwtProperties.getAccessTokenExpiration()))
                .refreshTokenTimeToLive(Duration.ofSeconds(jwtProperties.getRefreshTokenExpiration()))
                .reuseRefreshTokens(false)
                .build())
            .clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(false)
                .requireProofKey(true)
                .build());
        frontendProperties.getUrls().forEach(url -> {
            clientBuilder.redirectUri(url + "/");
            clientBuilder.redirectUri(url + "/oauth-popup.html");
        });
        RegisteredClient registeredClient = clientBuilder.build();
        logger.info("Registered client created with ID: {} and redirect URIs: {}", registeredClient.getClientId(), registeredClient.getRedirectUris());
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder(jwkSource));
        jwtGenerator.setJwtCustomizer(tokenCustomizer());
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        logger.info("OAuth2TokenGenerator configured with JWT generator and refresh token support");
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (context.getTokenType().getValue().equals(OAuth2TokenType.ACCESS_TOKEN.getValue())) {
                String username = context.getPrincipal().getName();
                logger.debug("Customizing JWT token for user: {}", username);
                User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> {
                        logger.error("User not found for token generation: {}", username);
                        return new RuntimeException("User not found: " + username);
                    });
                context.getClaims().claims(claims -> {
                    claims.put("sub", user.getId().toString());
                    claims.put("username", user.getUsername());
                    claims.put("email", user.getEmail());
                    claims.put("preferred_keyboard", user.getPreferredKeyboard().name());
                    claims.put("user_id", user.getId().toString());
                });
                logger.debug("JWT token customized - subject (UUID): {}, username: {}", user.getId(), user.getUsername());
            }
        };
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {
        RSAPublicKey publicKey = loadPublicKey();
        RSAPrivateKey privateKey = loadPrivateKey();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        logger.info("JWKSource configured with RSA key pair");
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private RSAPublicKey loadPublicKey() throws Exception {
        var resource = new ClassPathResource("certifications/public.pem");
        try (InputStream is = resource.getInputStream()) {
            String key = new String(is.readAllBytes())
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(key);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        }
    }

    private RSAPrivateKey loadPrivateKey() throws Exception {
        var resource = new ClassPathResource("certifications/private.pem");
        try (InputStream is = resource.getInputStream()) {
            String key = new String(is.readAllBytes())
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(key);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        }
    }
}
