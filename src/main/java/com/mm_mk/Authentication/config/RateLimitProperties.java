package com.mm_mk.Authentication.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Getter
@Setter
@Component
public class RateLimitProperties {

    private boolean enabled = true;
    private DefaultLimits defaults = new DefaultLimits();
    private Map<String, EndpointLimit> endpoints = new HashMap<>();

    @Getter
    @Setter
    public static class DefaultLimits {
        private int requests = 10;
        private Duration window = Duration.ofMinutes(1);
    }

    @Getter
    @Setter
    public static class EndpointLimit {
        private int requests;
        private Duration window;
        private boolean enabled = true;
    }

    public RateLimitProperties() {

        defaults.setRequests(10);
        defaults.setWindow(Duration.ofMinutes(1));

        EndpointLimit register = new EndpointLimit();
        register.setRequests(5);
        register.setWindow(Duration.ofMinutes(1));
        endpoints.put("/api/auth/register", register);

        EndpointLimit login = new EndpointLimit();
        login.setRequests(10);
        login.setWindow(Duration.ofMinutes(1));
        endpoints.put("/login", login);

        EndpointLimit oauth = new EndpointLimit();
        oauth.setRequests(10);
        oauth.setWindow(Duration.ofMinutes(1));
        endpoints.put("/oauth2/token", oauth);
    }
}
