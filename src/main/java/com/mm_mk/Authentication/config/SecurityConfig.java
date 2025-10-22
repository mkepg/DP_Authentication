package com.mm_mk.Authentication.config;


import com.mm_mk.Authentication.handler.FormLoginSuccessHandler;
import com.mm_mk.Authentication.handler.OAuth2AuthenticationSuccessHandler;
import com.mm_mk.Authentication.service.CustomOAuth2UserService;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.net.URI;
import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig {

    private final OAuth2AuthenticationSuccessHandler oAuth2SuccessHandler;
    private final FormLoginSuccessHandler formLoginSuccessHandler;
    private final CustomOAuth2UserService customOAuth2UserService;

    private final FrontendProperties frontendProperties;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authzServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http
                .securityMatcher(authzServerConfigurer.getEndpointsMatcher())
                .with(authzServerConfigurer, (authzServer) ->
                        authzServer
                                .oidc(withDefaults()) // Enable OpenID Connect
                )
                .authorizeHttpRequests(auth ->
                        auth.anyRequest().authenticated()
                )
                .cors(withDefaults())
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(authzServerConfigurer.getEndpointsMatcher())
                )
                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(withDefaults())
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                );

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(withDefaults())
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/auth/register",
                                "/login",
                                "/error",
                                "/public/**",
                                "/oauth2/**"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .successHandler(formLoginSuccessHandler)
                        .failureUrl("/login?error=true")
                        .permitAll()
                )
                .oauth2Login(oauth -> oauth
                        .loginPage("/login")
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customOAuth2UserService)
                        )
                        .successHandler(oAuth2SuccessHandler)
                )
                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(withDefaults())
                );

        return http.build();
    }


    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // Extract the origin (scheme + host + port) from each frontend URL
        List<String> allowedOrigins = frontendProperties.getUrls().stream()
                .map(uri -> {
                    try {
                        URI parsed = URI.create(uri);
                        return parsed.getScheme() + "://" + parsed.getHost() +
                                (parsed.getPort() != -1 ? ":" + parsed.getPort() : "");
                    } catch (Exception e) {
                        return null;
                    }
                })
                .filter(origin -> origin != null && !origin.isBlank())
                .distinct()
                .collect(Collectors.toList());

        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

}