package com.mm_mk.Authentication.config;

import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;

@Component
@Order(1)
public class CorrelationFilter extends OncePerRequestFilter {

    private static final String CORRELATION_ID_HEADER = "X-Correlation-ID";
    private static final String CORRELATION_ID_MDC_KEY = "correlationId";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String correlationId = getCorrelationIdFromHeader(request);

        try {
            MDC.put(CORRELATION_ID_MDC_KEY, correlationId);
            response.setHeader(CORRELATION_ID_HEADER, correlationId);

            logger.debug("Setting correlation ID: " + correlationId + " for request: " + request.getMethod() + request.getRequestURI());

            filterChain.doFilter(request, response);
        } finally {
            MDC.clear();
        }
    }

    private String getCorrelationIdFromHeader(HttpServletRequest request) {
        String correlationId = request.getHeader(CORRELATION_ID_HEADER);
        if (correlationId == null || correlationId.isBlank())
            correlationId = generateCorrelationId();
        return correlationId;
    }

    private String generateCorrelationId() {
        return "AUTH-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
    }
}
