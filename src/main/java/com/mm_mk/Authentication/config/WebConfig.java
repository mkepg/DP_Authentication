package com.mm_mk.Authentication.config;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@AllArgsConstructor
public class WebConfig implements WebMvcConfigurer {

    private final AppProperties appProperties;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        if (appProperties.getAuthorizedRedirectUris() == null || appProperties.getAuthorizedRedirectUris().isEmpty()) {
            return;
        }

        registry.addMapping("/**")
                .allowedOriginPatterns(appProperties.getAuthorizedRedirectUris().toArray(new String[0]))
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(false);
    }
}
