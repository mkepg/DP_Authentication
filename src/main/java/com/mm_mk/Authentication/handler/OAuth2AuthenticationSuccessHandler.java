package com.mm_mk.Authentication.handler;

import com.mm_mk.Authentication.config.AppProperties;
import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
import com.mm_mk.Authentication.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AppProperties appProperties;
    private final UserRepository userRepository;
    private final UserService userService;
    private final RequestCache requestCache;

    public OAuth2AuthenticationSuccessHandler(
            AppProperties appProperties,
            UserRepository userRepository,
            UserService userService,
            @Lazy RequestCache requestCache) {
        this.appProperties = appProperties;
        this.userRepository = userRepository;
        this.userService = userService;
        this.requestCache = requestCache;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();

        // Create or update local user
        createOrUpdateLocalUser(oauthUser);

        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            log.debug("Response has already been committed");
            return;
        }

        clearAuthenticationAttributes(request);

        log.info("OAuth2 login successful, redirecting to: {}", targetUrl);

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) {

        // Check if there's a saved request (OAuth2 authorization request)
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        if (savedRequest != null) {
            String redirectUrl = savedRequest.getRedirectUrl();
            log.info("Found saved request, resuming OAuth2 flow: {}", redirectUrl);

            // Clear the saved request
            requestCache.removeRequest(request, response);

            return redirectUrl;
        }

        // No saved request - redirect to default frontend
        log.info("No saved request found, redirecting to default URI");
        return appProperties.getDefaultRedirectUri();
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
}