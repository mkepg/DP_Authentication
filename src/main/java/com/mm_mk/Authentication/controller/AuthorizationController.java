package com.mm_mk.Authentication.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpSession;

@Controller
@RequiredArgsConstructor
public class AuthorizationController {

    @GetMapping("/oauth2/authorize")
    public String authorize(
            @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
            @RequestParam(OAuth2ParameterNames.REDIRECT_URI) String redirectUri,
            @RequestParam(OAuth2ParameterNames.RESPONSE_TYPE) String responseType,
            @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
            @RequestParam(value = OAuth2ParameterNames.STATE, required = false) String state,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
            HttpSession session) {

        // Store authorization request parameters in session
        session.setAttribute("authRequest_clientId", clientId);
        session.setAttribute("authRequest_redirectUri", redirectUri);
        session.setAttribute("authRequest_responseType", responseType);
        session.setAttribute("authRequest_scope", scope);
        session.setAttribute("authRequest_state", state);
        session.setAttribute("authRequest_codeChallenge", codeChallenge);
        session.setAttribute("authRequest_codeChallengeMethod", codeChallengeMethod);

        // Redirect to login page
        return "redirect:/login";
    }
}