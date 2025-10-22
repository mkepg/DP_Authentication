package com.mm_mk.Authentication.handler;

import com.mm_mk.Authentication.config.AppProperties;
import com.mm_mk.Authentication.repository.UserRepository;
import com.mm_mk.Authentication.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component("formLoginSuccessHandler")
public class FormLoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AppProperties appProperties;

    private final RequestCache requestCache;

    public FormLoginSuccessHandler(
            AppProperties appProperties,
            @Lazy RequestCache requestCache) {
        this.appProperties = appProperties;
        this.requestCache = requestCache;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            log.debug("Response has already been committed");
            return;
        }

        clearAuthenticationAttributes(request);

        log.info("Form login successful for user: {}, redirecting to: {}",
                authentication.getName(), targetUrl);

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

            // Clear the saved request since we're using it
            requestCache.removeRequest(request, response);

            // Return the saved OAuth2 authorization URL
            return redirectUrl;
        }

        // No saved request - redirect to default frontend
        log.info("No saved request found, redirecting to default URI");
        return appProperties.getDefaultRedirectUri();
    }
}