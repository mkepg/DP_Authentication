package com.mm_mk.Authentication.service;

import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
import com.mm_mk.Authentication.request.LoginRequest;
import com.mm_mk.Authentication.request.RegisterRequest;
import com.mm_mk.Authentication.response.AuthenticationResult;
import com.mm_mk.Authentication.response.UserDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    @Transactional
    public AuthenticationResult register(RegisterRequest req) {
        if (userRepository.existsByUsername(req.username())) {
            throw new IllegalArgumentException("Username already exists");
        }

        // Use the original 3-argument version - let database handle default
        User user = userService.createUser(
                req.username(),
                req.email(),
                passwordEncoder.encode(req.password())
        );

        UserDTO userDTO = new UserDTO(user.getId() ,user.getUsername(), user.getEmail(), user.getPreferredKeyboard());

        return new AuthenticationResult("Login successful", userDTO);

    }

//    public AuthenticationResult login(LoginRequest req) {
//
//        User user = null;
//
//        if ((req.username() == null || req.username().isBlank()) &&
//                (req.email() == null || req.email().isBlank())) {
//            throw new IllegalArgumentException("Username or email must be provided.");
//        }
//
//        if (req.password() == null || req.password().isBlank()) {
//            throw new IllegalArgumentException("Password must not be empty.");
//        }
//
//        String principal;
//        if (req.username() != null && !req.username().isBlank()) {
//            principal = req.username();
//        } else {
//            user = userRepository.findByEmail(req.email()).orElseThrow(() ->
//                    new IllegalArgumentException("No user found with the provided email."));
//            principal = user.getUsername();
//        }
//        try {
//            Authentication authentication = authenticationManager.authenticate(
//                    new UsernamePasswordAuthenticationToken(principal, req.password())
//            );
//
//            RegisteredClient registeredClient = registeredClientRepository.findByClientId("internal-client");
//            if (registeredClient == null) {
//                throw new IllegalStateException("OAuth client 'internal-client' is not registered.");
//            }
//
//            Instant issuedAt = Instant.now();
//            Instant expiresAt = issuedAt.plus(2, ChronoUnit.HOURS);
//            Set<String> scopes = Set.of("read", "write");
//
//            var claims = org.springframework.security.oauth2.jwt.JwtClaimsSet.builder()
//                    .issuer("http://localhost:8080")
//                    .issuedAt(issuedAt)
//                    .expiresAt(expiresAt)
//                    .subject(authentication.getName())
//                    .claim("scope", String.join(" ", scopes))
//                    .build();
//
//            Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims));
//
//            OAuth2AccessToken accessToken = new OAuth2AccessToken(
//                    OAuth2AccessToken.TokenType.BEARER,
//                    jwt.getTokenValue(),
//                    issuedAt,
//                    expiresAt,
//                    scopes
//            );
//
//            OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
//                    .principalName(authentication.getName())
//                    .authorizationGrantType(new org.springframework.security.oauth2.core.AuthorizationGrantType("password"))
//                    .attribute(Authentication.class.getName(), authentication)
//                    .token(accessToken, metadata ->
//                            metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwt.getClaims()))
//                    .build();
//
//            authorizationService.save(authorization);
//
//            if(user == null) {
//                user = userRepository.findByUsername(authentication.getName())
//                        .or(() -> userRepository.findByEmail(authentication.getName()))
//                        .orElseThrow(() -> new IllegalStateException("Authenticated user record not found."));
//
//            }
//
//            UserDTO userDTO = new UserDTO(user.getId() ,user.getUsername(), user.getEmail(), user.getPreferredKeyboard());
//
//            return new AuthenticationResult("Login successful", jwt.getTokenValue(), userDTO);
//
//        } catch (AuthenticationException ex) {
//            throw new IllegalArgumentException("Invalid username/email or password.");
//        } catch (IllegalArgumentException ex) {
//            throw ex;
//        } catch (Exception ex) {
//            throw new RuntimeException("Login failed due to an internal error.", ex);
//        }
//    }
}








//package com.mm_mk.Authentication.service;
//
//import com.mm_mk.Authentication.repository.UserRepository;
//import com.mm_mk.Authentication.response.AuthenticationResult;
//import com.mm_mk.Authentication.response.UserDTO;
//import com.mm_mk.Authentication.util.JwtUtils;
//import com.mm_mk.Authentication.model.User;
//import com.mm_mk.Authentication.request.LoginRequest;
//import com.mm_mk.Authentication.request.RegisterRequest;
//import lombok.RequiredArgsConstructor;
//import org.springframework.amqp.rabbit.core.RabbitTemplate;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Service;
//import org.springframework.transaction.annotation.Transactional;
//
//@Service
//@RequiredArgsConstructor
//public class AuthService {
//
//    private final UserRepository repo;
//    private final UserService userService;
//    private final PasswordEncoder encoder;
//    private final JpaUserDetailsService jpaUserDetailsService;
//    private final JwtUtils jwtUtils;
//    private final RabbitTemplate rabbitTemplate;
//
//    @Transactional
//    public AuthenticationResult register(RegisterRequest req) {
//        if (repo.existsByUsername(req.username())) {
//            throw new IllegalArgumentException("Username already exists");
//        }
//
//        User user = userService.createUser(
//                req.username(),
//                req.email(),
//                encoder.encode(req.password())
//        );
//
//        UserDetails userDetails = jpaUserDetailsService.loadUserByUsername(user.getUsername());
//        String token = jwtUtils.generateToken(userDetails);
//
//        UserDTO userDTO = new UserDTO(
//                user.getUsername(),
//                user.getEmail(),
//                user.getPreferredKeyboard()
//        );
//
//        return new AuthenticationResult("User " + userDetails.getUsername() + " is successfully registered", token, userDTO);
//    }
//
//    @Transactional(readOnly = true)
//    public AuthenticationResult login(LoginRequest req) {
//        if ((req.username() == null || req.username().isBlank()) &&
//                (req.email() == null || req.email().isBlank())) {
//            throw new IllegalArgumentException("Username or email must be provided");
//        }
//
//        User user;
//        UserDetails userDetails;
//
//        if (req.username() != null && !req.username().isBlank()) {
//            user = repo.findByUsername(req.username())
//                    .orElseThrow(() -> new UsernameNotFoundException("No user with username: " + req.username()));
//            userDetails = jpaUserDetailsService.loadUserByUsername(req.username());
//        } else {
//            user = repo.findByEmail(req.email())
//                    .orElseThrow(() -> new UsernameNotFoundException("No user with email: " + req.email()));
//            userDetails = jpaUserDetailsService.loadUserByEmail(req.email());
//        }
//
//        if (!encoder.matches(req.password(), userDetails.getPassword()))
//            throw new IllegalArgumentException("Invalid password");
//
//        String token = jwtUtils.generateToken(userDetails);
//
//        UserDTO userDTO = new UserDTO(
//                user.getUsername(),
//                user.getEmail(),
//                user.getPreferredKeyboard()
//        );
//
//        return new AuthenticationResult("Login successfully", token, userDTO);
//    }
//
//}

