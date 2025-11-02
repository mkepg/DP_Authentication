package com.mm_mk.Authentication.config;

import com.mm_mk.Authentication.service.RateLimitService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.regex.Pattern;

@Component
@Order(0)
@RequiredArgsConstructor
public class RateLimitFilter implements Filter {

    private final RateLimitService rateLimitService;
    private final RateLimitProperties properties;

    private static final int SC_TOO_MANY_REQUESTS = 429;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!properties.isEnabled()) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String path = req.getRequestURI();
        String clientIp = getClientIp(req);

        if (shouldSkipRateLimit(path)) {
            chain.doFilter(request, response);
            return;
        }

        RateLimitProperties.EndpointLimit endpointLimit = resolveEndpointLimit(path);
        if (endpointLimit == null || !endpointLimit.isEnabled()) {
            endpointLimit = new RateLimitProperties.EndpointLimit();
            endpointLimit.setRequests(properties.getDefaults().getRequests());
            endpointLimit.setWindow(properties.getDefaults().getWindow());
        }

        int limit = endpointLimit.getRequests();
        Duration window = endpointLimit.getWindow();
        String category = normalizeCategoryKey(path, endpointLimit);
        String key = clientIp + ":" + category;

        if (!rateLimitService.isAllowed(key, limit, window, category)) {
            handleRateLimitExceeded(res, window);
            return;
        }

        int remaining = rateLimitService.getRemaining(key, limit, category);
        addRateLimitHeaders(res, limit, remaining, window);
        chain.doFilter(request, response);
    }

    private boolean shouldSkipRateLimit(String path) {
        if (path == null) return true;
        return path.startsWith("/actuator/health")
                || path.startsWith("/actuator/info")
                || path.startsWith("/swagger-ui")
                || path.startsWith("/v3/api-docs")
                || path.startsWith("/api-docs")
                || path.startsWith("/error");
    }

    private RateLimitProperties.EndpointLimit resolveEndpointLimit(String path) {
        RateLimitProperties.EndpointLimit bestMatch = null;
        int bestScore = -1;

        for (Map.Entry<String, RateLimitProperties.EndpointLimit> entry : properties.getEndpoints().entrySet()) {
            String pattern = entry.getKey();
            if (matchesPattern(pattern, path)) {
                int score = pattern.length();
                if (score > bestScore) {
                    bestMatch = entry.getValue();
                    bestScore = score;
                }
            }
        }
        return bestMatch;
    }

    private boolean matchesPattern(String pattern, String path) {
        if (pattern == null || path == null) return false;

        // Convert wildcards to regex
        String regex = pattern
                .replace(".", "\\.")
                .replace("/**", "(/.*)?")
                .replace("/*", "/[^/]+");

        return Pattern.matches("^" + regex + "$", path);
    }

    private String normalizeCategoryKey(String path, RateLimitProperties.EndpointLimit endpointLimit) {
        for (String pattern : properties.getEndpoints().keySet()) {
            if (matchesPattern(pattern, path)) return pattern;
        }
        return "default";
    }

    private void handleRateLimitExceeded(HttpServletResponse res, Duration window) throws IOException {
        res.setStatus(SC_TOO_MANY_REQUESTS);
        res.setContentType("application/json");
        res.setHeader("Retry-After", String.valueOf(window.toSeconds()));

        String body = String.format(
                "{\"error\":\"Rate limit exceeded\",\"message\":\"Too many requests. Try again in %d seconds.\",\"retryAfter\":%d}",
                window.toSeconds(), window.toSeconds()
        );
        res.getWriter().write(body);
    }

    private void addRateLimitHeaders(HttpServletResponse res, int limit, int remaining, Duration window) {
        res.setHeader("X-RateLimit-Limit", String.valueOf(limit));
        res.setHeader("X-RateLimit-Remaining", String.valueOf(remaining));
        res.setHeader("X-RateLimit-Reset", String.valueOf(System.currentTimeMillis() + window.toMillis()));
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isBlank()) ip = request.getHeader("X-Real-IP");
        if (ip == null || ip.isBlank()) ip = request.getRemoteAddr();
        if (ip != null && ip.contains(",")) ip = ip.split(",")[0].trim();
        return ip != null ? ip : "unknown";
    }
}
