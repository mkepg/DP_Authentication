package com.mm_mk.Authentication.handler;

import com.mm_mk.Authentication.config.AppProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component("formLoginSuccessHandler")
@RequiredArgsConstructor
public class FormLoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AppProperties appProperties;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        // Get the saved request (where user was trying to go before login)
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            log.debug("Response has already been committed");
            return;
        }

        clearAuthenticationAttributes(request);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) {
        // Spring Security will automatically resume the OAuth2 flow
        // by redirecting back to /oauth2/authorize
        String targetUrl = super.determineTargetUrl(request, response, authentication);

        // If there's no saved request, redirect to default
        if (targetUrl.equals("/")) {
            targetUrl = appProperties.getDefaultRedirectUri();
        }

        log.info("Form login successful for user: {}, redirecting to: {}",
                authentication.getName(), targetUrl);

        return targetUrl;
    }
}