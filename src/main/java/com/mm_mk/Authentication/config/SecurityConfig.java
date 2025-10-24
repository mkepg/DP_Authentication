package com.mm_mk.Authentication.config;

import com.mm_mk.Authentication.handler.OAuth2AuthenticationSuccessHandler;
import com.mm_mk.Authentication.oauth2.PasswordPkceGrantAuthenticationConverter;
import com.mm_mk.Authentication.oauth2.PasswordPkceGrantAuthenticationProvider;
import com.mm_mk.Authentication.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final OAuth2AuthenticationSuccessHandler oAuth2SuccessHandler;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final FrontendProperties frontendProperties;
    private final PasswordPkceGrantAuthenticationProvider passwordPkceGrantAuthenticationProvider;
    private static final Logger log = LoggerFactory.getLogger(PasswordPkceGrantAuthenticationProvider.class);
    private final RegisteredClientRepository registeredClientRepository;
    private final UserDetailsService userDetailsService;


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        log.info("=== Configuring Authorization Server Security Filter Chain ===");

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (configurer) -> {
                    log.info("Configuring OAuth2 Authorization Server with OIDC");
                    configurer.oidc(Customizer.withDefaults());
                    configurer.tokenEndpoint(tokenEndpoint -> {
                        log.info("Registering Enhanced PasswordPkceGrantAuthenticationConverter");
                        tokenEndpoint.accessTokenRequestConverter(new PasswordPkceGrantAuthenticationConverter(registeredClientRepository));
                    });

                    configurer.authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint.consentPage("/oauth2/consent"));
                })
                .cors(cors -> cors.configurationSource(corsConfigurationSource(frontendProperties)))
                .authorizeHttpRequests(authorize -> {
                    log.info("Authorization Server - permitting all requests to OAuth2 endpoints");
                    authorize.anyRequest().permitAll();
                })
                .csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher()))
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        log.info("Registering PasswordPkceGrantAuthenticationProvider");
        http.authenticationProvider(passwordPkceGrantAuthenticationProvider);
        http.authenticationProvider(daoAuthenticationProvider());
        log.info("Authorization Server Security Filter Chain configured");
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/auth/register",
                                "/api/auth/login",
                                "/login",
                                "/error",
                                "/public/**",
                                "/oauth2/token",
                                "/oauth2/authorize/**",
                                "/oauth2/**",
                                "/.well-known/**",
                                "/userinfo",
                                "/oauth-success"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .successHandler(oAuth2SuccessHandler)
                        .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                )
                .oauth2Client(Customizer.withDefaults())
                .formLogin(form -> form
                        .loginPage("/login")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout=true")
                        .permitAll()
                );

        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(FrontendProperties frontendProperties) {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(frontendProperties.getUrls());

        List<String> allowedOrigins = new ArrayList<>(frontendProperties.getUrls());
        allowedOrigins.add("http://localhost:5173/oauth-popup.html");
        allowedOrigins.add("http://localhost:5174/oauth-popup.html");
        configuration.setAllowedOrigins(allowedOrigins);

        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With"));
        configuration.setExposedHeaders(Arrays.asList("Authorization"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L); // 1h

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
