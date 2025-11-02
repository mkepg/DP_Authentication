package com.mm_mk.Authentication.config;

import com.mm_mk.Authentication.handler.OAuth2AuthenticationSuccessHandler;
import com.mm_mk.Authentication.oauth2.PasswordPkceGrantAuthenticationConverter;
import com.mm_mk.Authentication.oauth2.PasswordPkceGrantAuthenticationProvider;
import com.mm_mk.Authentication.repository.AdminUserRepository;
import com.mm_mk.Authentication.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.web.authentication.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.security.oauth2.server.authorization.web.authentication.*;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;

import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;
import java.util.UUID;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
    private final OAuth2AuthenticationSuccessHandler oAuth2SuccessHandler;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final FrontendProperties frontendProperties;
    private final PasswordPkceGrantAuthenticationProvider passwordPkceGrantAuthenticationProvider;
    private final RegisteredClientRepository registeredClientRepository;
    private final UserDetailsService userDetailsService;
    private final ActuatorUserAgentFilter actuatorUserAgentFilter;
    private final CorrelationFilter correlationFilter;
    private final AdminUserRepository adminUserRepository;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain actuatorSecurity(HttpSecurity http) throws Exception {
        logger.info("=== Configuring Actuator Security Filter Chain ===");
        http
                .securityMatcher("/actuator/**", "/swagger-ui/**", "/v3/api-docs/**", "/api-docs/**")
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/api-docs/**").permitAll()
                        .anyRequest().hasRole("ADMIN")
                )
                .httpBasic(Customizer.withDefaults())
                .formLogin(form -> form.disable())
                .addFilterBefore(correlationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(actuatorUserAgentFilter, UsernamePasswordAuthenticationFilter.class);

        logger.info("Actuator security configured");
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        logger.info("=== Configuring OAuth2 Authorisation-Server Chain ===");
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, cfg -> {
                    cfg.oidc(Customizer.withDefaults());
                    cfg.tokenEndpoint(token ->
                            token.accessTokenRequestConverter(
                                    new DelegatingAuthenticationConverter(
                                            Arrays.asList(
                                                    new PasswordPkceGrantAuthenticationConverter(registeredClientRepository), // Your custom one first
                                                    new OAuth2AuthorizationCodeAuthenticationConverter(),
                                                    new OAuth2RefreshTokenAuthenticationConverter(),  // This handles refresh_token
                                                    new OAuth2ClientCredentialsAuthenticationConverter(),
                                                    new OAuth2DeviceCodeAuthenticationConverter(),
                                                    new OAuth2TokenExchangeAuthenticationConverter()
                                            )
                                    )
                            )
                    );
                    cfg.authorizationEndpoint(authz ->
                            authz.consentPage("/oauth2/consent")
                    );
                })
                .cors(cors -> cors.configurationSource(corsConfigurationSource(frontendProperties)))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .ignoringRequestMatchers(
                                "/oauth2/**",
                                "/login/oauth2/**"
                        )
                )
                .exceptionHandling(ex -> ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        http.authenticationProvider(passwordPkceGrantAuthenticationProvider).authenticationProvider(daoAuthenticationProvider());

        logger.info("OAuth2 chain configured");
        return http.build();
    }

    @Bean
    @Order(3)
    public SecurityFilterChain apiJwtChain(HttpSecurity http) throws Exception {
        logger.info("=== Configuring Stateless JWT Chain (/api/auth/**) ===");

        http
                .securityMatcher("/api/auth/**")
                .cors(cors -> cors.configurationSource(corsConfigurationSource(frontendProperties)))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS).permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/register").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())));

        logger.info("JWT chain configured");
        return http.build();
    }

    @Bean
    @Order(4)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        logger.info("=== Configuring Default (Session) Filter Chain ===");

        http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .ignoringRequestMatchers(
                                "/oauth2/**",
                                "/login/oauth2/**",
                                "/ws/**",
                                "/public/**"
                        )
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/csrf",
                                "/login",
                                "/error",
                                "/oauth-success",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/api-docs/**",
                                "/ws/**"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(correlationFilter, UsernamePasswordAuthenticationFilter.class)
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .successHandler(oAuth2SuccessHandler)
                        .userInfoEndpoint(uie -> uie.userService(customOAuth2UserService))
                )
                .oauth2Client(Customizer.withDefaults())
                .formLogin(form -> form.disable())
                .logout(logout -> logout.logoutSuccessUrl("/login?logout=true").permitAll());

        logger.info("Default session chain configured");
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
        logger.info("Configuring CORS with allowed origins: {}", frontendProperties.getUrls());

        CorsConfiguration cfg = new CorsConfiguration();
        List<String> allowedOrigins = new ArrayList<>(frontendProperties.getUrls());
        allowedOrigins.add("http://localhost:5173/oauth-popup.html");
        allowedOrigins.add("http://localhost:5174/oauth-popup.html");

        cfg.setAllowedOrigins(allowedOrigins);
        cfg.setAllowedMethods(Arrays.asList("GET","POST","PUT","DELETE","OPTIONS","PATCH"));
        cfg.setAllowedHeaders(Arrays.asList(
                "Authorization","Content-Type","X-Requested-With","X-XSRF-TOKEN","X-Correlation-ID"
        ));
        cfg.setExposedHeaders(Arrays.asList(
                "Authorization","X-XSRF-TOKEN","X-Correlation-ID"
        ));
        cfg.setAllowCredentials(true);
        cfg.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        return new JwtAuthenticationConverter() {{
            setJwtGrantedAuthoritiesConverter(jwt -> {
                UUID userId = UUID.fromString(jwt.getSubject());
                List<GrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                if (adminUserRepository.isUserAdmin(userId)) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
                }
                return authorities;
            });
        }};
    }

}