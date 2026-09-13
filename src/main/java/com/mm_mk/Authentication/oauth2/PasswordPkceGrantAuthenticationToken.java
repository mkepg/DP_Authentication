package com.mm_mk.Authentication.oauth2;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;

public class PasswordPkceGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final String username;
    private final String password;
    private final String codeChallenge;
    private final String codeChallengeMethod;

    public PasswordPkceGrantAuthenticationToken(
            String username,
            String password,
            String codeChallenge,
            String codeChallengeMethod,
            Authentication clientPrincipal,
            Map<String, Object> additionalParameters
    ) {
        super(new AuthorizationGrantType("password_pkce"), clientPrincipal, additionalParameters);
        this.username = username;
        this.password = password;
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
    }

    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public String getCodeChallenge() { return codeChallenge; }
    public String getCodeChallengeMethod() { return codeChallengeMethod; }
}
