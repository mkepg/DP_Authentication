package com.mm_mk.Authentication.service;

import com.mm_mk.Authentication.event.UserCreatedEvent;
import com.mm_mk.Authentication.model.KeyboardModel;
import com.mm_mk.Authentication.model.User;
import com.mm_mk.Authentication.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

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

        UserCreatedEvent event = UserCreatedEvent.builder()
                .id(saved.getId())
                .username(saved.getUsername())
                .email(saved.getEmail())
                .preferredKeyboard(saved.getPreferredKeyboard().name())
                .build();

        rabbitTemplate.convertAndSend("user.exchange", "", event);
        return saved;
    }
}

