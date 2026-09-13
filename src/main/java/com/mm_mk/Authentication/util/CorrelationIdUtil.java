package com.mm_mk.Authentication.util;

import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class CorrelationIdUtil {

    private static final String CORRELATION_ID_MDC_KEY = "correlationId";

    public static String getCorrelationId() {
        String correlationId = MDC.get(CORRELATION_ID_MDC_KEY);
        if (correlationId == null || correlationId.isBlank()) {
            correlationId = generateCorrelationId();
            MDC.put(CORRELATION_ID_MDC_KEY, correlationId);
        }
        return correlationId;
    }

    public static void setCorrelationId(String correlationId) {
        if (correlationId != null && !correlationId.isBlank()) {
            MDC.put(CORRELATION_ID_MDC_KEY, correlationId);
        }
    }

    public static void clear() {
        MDC.clear();
    }

    public static String generateCorrelationId() {
        return "AUTH-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
    }

    public static boolean hasCorrelationId() {
        return MDC.get(CORRELATION_ID_MDC_KEY) != null;
    }
}
