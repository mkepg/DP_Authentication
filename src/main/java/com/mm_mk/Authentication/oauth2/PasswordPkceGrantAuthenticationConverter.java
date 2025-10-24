package com.mm_mk.Authentication.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class PasswordPkceGrantAuthenticationConverter implements AuthenticationConverter {

    private static final Logger log = LoggerFactory.getLogger(PasswordPkceGrantAuthenticationConverter.class);
    private static final String GRANT_TYPE = "password_pkce";
    private final RegisteredClientRepository registeredClientRepository;

    public PasswordPkceGrantAuthenticationConverter(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        log.info("=== OAuth2 Token Endpoint Called ===");
        log.info("Grant Type: {}", grantType);
        log.info("Request Method: {}", request.getMethod());
        log.info("Request URI: {}", request.getRequestURI());

        if (!GRANT_TYPE.equals(grantType)) {
            log.warn("Grant type mismatch - expected '{}' but got '{}'", GRANT_TYPE, grantType);
            return null;
        }

        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        log.info("Client ID from request: {}", clientId);

        if (!StringUtils.hasText(clientId)) {
            log.error("Missing client_id parameter");
            return null;
        }

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            log.error("Client not found: {}", clientId);
            return null;
        }

        log.info("Found registered client: {}", registeredClient.getClientId());
        log.info("Client authentication methods: {}", registeredClient.getClientAuthenticationMethods());

        if (!registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
            log.error("Client {} is not configured for public authentication", clientId);
            return null;
        }

        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
                registeredClient, ClientAuthenticationMethod.NONE, null);

        log.info("✅ Public client authenticated: {}", clientId);

        String username = request.getParameter("username");
        String password = request.getParameter("password");
        String codeChallenge = request.getParameter("code_challenge");
        String codeChallengeMethod = request.getParameter("code_challenge_method");
        String scope = request.getParameter(OAuth2ParameterNames.SCOPE);

        log.info("Username: {}", username);
        log.info("Password: {}", password != null ? "[PROVIDED]" : "null");
        log.info("Code Challenge: {}", codeChallenge);
        log.info("Code Challenge Method: {}", codeChallengeMethod);
        log.info("Scope: {}", scope);

        if (!StringUtils.hasText(username)) {
            log.error("Missing required parameter: username");
            return null;
        }
        if (!StringUtils.hasText(password)) {
            log.error("Missing required parameter: password");
            return null;
        }
        if (!StringUtils.hasText(codeChallenge)) {
            log.error("Missing required parameter: code_challenge");
            return null;
        }
        if (!StringUtils.hasText(codeChallengeMethod)) {
            log.error("Missing required parameter: code_challenge_method");
            return null;
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        request.getParameterMap().forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                    !key.equals(OAuth2ParameterNames.CLIENT_ID) &&
                    !key.equals("username") && !key.equals("password") &&
                    !key.equals("code_challenge") && !key.equals("code_challenge_method")) {
                additionalParameters.put(key, value.length == 1 ? value[0] : value);
            }
        });

        log.info("Additional Parameters: {}", additionalParameters);
        log.info("Creating PasswordPkceGrantAuthenticationToken");

        return new PasswordPkceGrantAuthenticationToken(username, password, codeChallenge, codeChallengeMethod, clientPrincipal, additionalParameters);
    }
}