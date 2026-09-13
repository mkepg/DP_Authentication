package com.mm_mk.Authentication.handler;

import com.mm_mk.Authentication.config.AppProperties;
import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
import com.mm_mk.Authentication.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AppProperties appProperties;
    private final UserRepository userRepository;
    private final UserService userService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
        User user = createOrUpdateLocalUser(oauthUser);
        log.info("OAuth2 login successful for user: {}, redirecting to success page", user.getUsername());
        String successUrl = "/oauth-success";
        getRedirectStrategy().sendRedirect(request, response, successUrl);
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String redirectUri = request.getParameter("redirect_uri");
        if (redirectUri != null && !redirectUri.isBlank())
            return redirectUri;
        return appProperties.getDefaultRedirectUri();
    }

    private User createOrUpdateLocalUser(OAuth2User oauthUser) {
        String name = (String) oauthUser.getAttributes().get("name");
        String email = (String) oauthUser.getAttributes().get("email");
        if (email == null) throw new IllegalStateException("Email not found from OAuth2 provider");

        return userRepository.findByEmail(email)
                .map(existingUser -> {
                    if (name != null && !name.equals(existingUser.getUsername())) {
                        existingUser.setUsername(name);
                        return userRepository.save(existingUser);
                    }
                    return existingUser;
                })
                .orElseGet(() -> {
                    String username = name != null ? name : email.split("@")[0];
                    String uniqueUsername = username;
                    int counter = 1;
                    while (userRepository.findByUsername(uniqueUsername).isPresent()) {
                        uniqueUsername = username + counter;
                        counter++;
                    }
                    String randomPassword = java.util.UUID.randomUUID().toString();
                    return userService.createUser(uniqueUsername, email, randomPassword);
                });
    }
}
