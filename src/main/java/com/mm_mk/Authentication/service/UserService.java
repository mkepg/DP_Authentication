package com.mm_mk.Authentication.service;

import com.mm_mk.Authentication.event.UserCreatedEvent;
import com.mm_mk.Authentication.event.UserUpdatedEvent;
import com.mm_mk.Authentication.model.KeyboardModel;
import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
import com.mm_mk.Authentication.request.UpdateUserRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository repo;
    private final RabbitTemplate rabbitTemplate;

    @Transactional
    public User createUser(String username, String email, String passwordHash) {
        User user = User.builder()
                .username(username)
                .email(email)
                .passwordHash(passwordHash)
                .build();

        User saved = repo.save(user);

        // Ensure we have the actual value from database
        String keyboardValue = Optional.ofNullable(saved.getPreferredKeyboard())
                .map(KeyboardModel::name)
                .orElse("Casio");

        UserCreatedEvent event = UserCreatedEvent.builder()
                .id(saved.getId())
                .username(saved.getUsername())
                .email(saved.getEmail())
                .preferredKeyboard(keyboardValue)
                .build();

        rabbitTemplate.convertAndSend("user.exchange", "", event);
        return saved;
    }

    @Transactional
    public User updateUser(UUID userId, UpdateUserRequest updateRequest) {
        User user = repo.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (updateRequest.username() != null && !updateRequest.username().isBlank()) {
            if (repo.findByUsername(updateRequest.username())
                    .filter(existing -> !existing.getId().equals(userId))
                    .isPresent()) {
                throw new IllegalArgumentException("Username already taken");
            }
            user.setUsername(updateRequest.username());
        }

        if (updateRequest.preferredKeyboard() != null) {
            user.setPreferredKeyboard(updateRequest.preferredKeyboard());
        }

        User updated = repo.save(user);

        UserUpdatedEvent event = UserUpdatedEvent.builder()
                .id(updated.getId())
                .username(updated.getUsername())
                .email(updated.getEmail())
                .preferredKeyboard(updated.getPreferredKeyboard().name())
                .build();

        rabbitTemplate.convertAndSend("user.exchange", "", event);
        return updated;
    }
}

