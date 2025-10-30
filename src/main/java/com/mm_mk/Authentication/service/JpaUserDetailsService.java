package com.mm_mk.Authentication.service;

import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.AdminUserRepository;
import com.mm_mk.Authentication.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Component
public class JpaUserDetailsService implements UserDetailsService {
    private static final Logger logger = LoggerFactory.getLogger(JpaUserDetailsService.class);
    private final UserRepository userRepository;
    private final AdminUserRepository adminUserRepository;

    public JpaUserDetailsService(UserRepository userRepository, AdminUserRepository adminUserRepository) {
        this.userRepository = userRepository;
        this.adminUserRepository = adminUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        logger.debug("Loading user by username or email: {}", usernameOrEmail);

        Optional<User> user = userRepository.findByUsername(usernameOrEmail);
        if (user.isEmpty() && usernameOrEmail.contains("@")) {
            user = userRepository.findByEmail(usernameOrEmail);
        }

        return user.map(this::toUserDetails)
                .orElseThrow(() -> new UsernameNotFoundException("No user with username or email: " + usernameOrEmail));
    }

    private UserDetails toUserDetails(User user) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();

        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        boolean isAdmin = adminUserRepository.isUserAdmin(user.getId());
        if (isAdmin) {
            authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            logger.debug("User {} granted ROLE_ADMIN", user.getUsername());
        }

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPasswordHash(),
                authorities
        );
    }
}