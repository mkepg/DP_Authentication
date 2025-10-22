package com.mm_mk.Authentication.event;

import lombok.*;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserUpdatedEvent {
    private UUID id;
    private String username;
    private String preferredKeyboard;
}
