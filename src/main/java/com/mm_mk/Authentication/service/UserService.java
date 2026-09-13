package com.mm_mk.Authentication.service;

import com.mm_mk.Authentication.event.UserCreatedEvent;
import com.mm_mk.Authentication.event.UserUpdatedEvent;
import com.mm_mk.Authentication.model.KeyboardModel;
import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
import com.mm_mk.Authentication.request.UpdateUserRequest;
import com.mm_mk.Authentication.util.CorrelationIdUtil;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    private static final long SLOW_OPERATION_THRESHOLD_MS = 1000;
    private final UserRepository repo;
    private final RabbitTemplate rabbitTemplate;

    @Transactional
    public User createUser(String username, String email, String passwordHash) {
        long startTime = System.currentTimeMillis();
        logger.info("Creating user - username: {}, email: {}", username, email);

        try {
            User user = User.builder()
                    .username(username)
                    .email(email)
                    .passwordHash(passwordHash)
                    .build();

            User saved = repo.save(user);
            logger.debug("User saved successfully - userId: {}, username: {}", saved.getId(), saved.getUsername());

            String keyboardValue = Optional.ofNullable(saved.getPreferredKeyboard())
                    .map(KeyboardModel::name)
                    .orElse("Casio");

            UserCreatedEvent event = UserCreatedEvent.builder()
                    .id(saved.getId())
                    .username(saved.getUsername())
                    .preferredKeyboard(keyboardValue)
                    .build();

            rabbitTemplate.convertAndSend("user.exchange", "user.created", event, amqpMessage -> {
                amqpMessage.getMessageProperties().setHeader("X-Correlation-ID", CorrelationIdUtil.getCorrelationId());
                return amqpMessage;
            });

            logger.info("User created event sent - userId: {}, username: {}", saved.getId(), saved.getUsername());
            return saved;
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            logger.info("User creation completed in {}ms", duration);
            if (duration > SLOW_OPERATION_THRESHOLD_MS)
                logger.warn("SLOW OPERATION: User creation took {}ms", duration);
        }
    }

    @Transactional
    public User updateUser(UUID userId, UpdateUserRequest updateRequest) {
        long startTime = System.currentTimeMillis();
        logger.info("Updating user - userId: {}, newUsername: {}, newKeyboard: {}", userId, updateRequest.username(), updateRequest.preferredKeyboard());

        try {
            User user = repo.findById(userId)
                    .orElseThrow(() -> {
                        logger.error("User not found for update - userId: {}", userId);
                        return new IllegalArgumentException("User not found");
                    });

            if (updateRequest.username() != null && !updateRequest.username().isBlank()) {
                if (repo.findByUsername(updateRequest.username())
                        .filter(existing -> !existing.getId().equals(userId))
                        .isPresent()) {
                    logger.warn("Username already taken - requested: {}, userId: {}", updateRequest.username(), userId);
                    throw new IllegalArgumentException("Username already taken");
                }
                user.setUsername(updateRequest.username());
                logger.debug("Username updated for userId: {}", userId);
            }

            if (updateRequest.preferredKeyboard() != null) {
                user.setPreferredKeyboard(updateRequest.preferredKeyboard());
                logger.debug("Keyboard preference updated for userId: {}", userId);
            }

            User updated = repo.save(user);
            logger.debug("User updated successfully - userId: {}, newUsername: {}", userId, updated.getUsername());

            UserUpdatedEvent event = UserUpdatedEvent.builder()
                    .id(updated.getId())
                    .username(updated.getUsername())
                    .preferredKeyboard(updated.getPreferredKeyboard().name())
                    .build();

            rabbitTemplate.convertAndSend("user.exchange", "user.updated", event, amqpMessage -> {
                amqpMessage.getMessageProperties().setHeader("X-Correlation-ID", CorrelationIdUtil.getCorrelationId());
                return amqpMessage;
            });

            logger.info("User updated event sent - userId: {}, username: {}", updated.getId(), updated.getUsername());
            return updated;
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            logger.info("User update completed in {}ms", duration);
            if (duration > SLOW_OPERATION_THRESHOLD_MS)
                logger.warn("SLOW OPERATION: User update took {}ms", duration);
        }
    }
}
