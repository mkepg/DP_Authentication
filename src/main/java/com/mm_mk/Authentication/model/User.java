package com.mm_mk.Authentication.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "users", schema = "public")
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
    private UUID id;

    @Column(name = "username", length = 50, nullable = false, unique = true)
    private String username;

    @Column(name = "email", length = 100, nullable = false, unique = true)
    private String email;

    @Column(name = "password_hash", length = 255, nullable = false)
    private String passwordHash;

    @Column(name = "provider", length = 50)
    private String provider;

    @Column(name = "provider_id", length = 255)
    private String providerId;

    @Builder.Default
    @Enumerated(EnumType.STRING)
    @Column(name = "preferred_keyboard")
    private KeyboardModel preferredKeyboard = KeyboardModel.Casio;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", passwordHash='" + passwordHash + '\'' +
                ", provider='" + provider + '\'' +
                ", providerId='" + providerId + '\'' +
                ", preferredKeyboard=" + preferredKeyboard +
                ", createdAt=" + createdAt +
                ", updatedAt=" + updatedAt +
                '}';
    }
}
