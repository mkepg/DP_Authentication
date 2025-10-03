package com.mm_mk.Authentication.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "app.oauth2")
public class AppProperties {
    private String defaultRedirectUri;
    private List<String> authorizedRedirectUris;
}
