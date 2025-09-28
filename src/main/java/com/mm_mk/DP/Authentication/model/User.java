package com.mm_mk.DP.Authentication.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "users", schema = "auth")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class User {

    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id; // Internal user identifier

    @Column(name = "username", length = 50, nullable = false, unique = true)
    private String username; // Login name (used by Spring Security)

    @Column(name = "email", length = 100, nullable = false, unique = true)
    private String email; // For communication and OAuth mapping

    @Column(name = "password_hash", length = 255, nullable = false)
    private String passwordHash; // Bcrypt hash for Spring Security

    @Column(name = "provider", length = 50)
    private String provider; // e.g., 'local', 'google', 'github'

    @Column(name = "provider_id", length = 255)
    private String providerId; // External OAuth provider unique id

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt; // Automatically set when created

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt; // Automatically updated when entity changes

    public User(UUID id, String username, String email, String passwordHash,
                String provider, String providerId) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.passwordHash = passwordHash;
        this.provider = provider;
        this.providerId = providerId;
    }
}