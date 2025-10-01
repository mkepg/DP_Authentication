// src/main/java/com/mm_mk/Authentication/event/UserCreatedEvent.java
package com.mm_mk.Authentication.event;

import lombok.*;

import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserCreatedEvent {
    private UUID id;        // Same as auth.users.id
    private String username;
    private String email;
}
