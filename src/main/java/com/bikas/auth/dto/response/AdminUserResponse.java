package com.bikas.auth.dto.response;

import com.bikas.auth.model.Role;
import com.bikas.auth.model.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * Admin user management response DTO
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AdminUserResponse {

    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private Set<Role> roles;
    private Boolean emailVerified;
    private Boolean enabled;
    private Boolean accountNonLocked;
    private Integer failedLoginAttempts;
    private LocalDateTime accountLockedUntil;
    private LocalDateTime lastLogin;
    private LocalDateTime passwordChangedAt;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public static AdminUserResponse fromUser(User user) {
        return AdminUserResponse.builder()
                .id(user.getId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .roles(user.getRoles())
                .emailVerified(user.getEmailVerified())
                .enabled(user.getEnabled())
                .accountNonLocked(user.getAccountNonLocked())
                .failedLoginAttempts(user.getFailedLoginAttempts())
                .accountLockedUntil(user.getAccountLockedUntil())
                .lastLogin(user.getLastLogin())
                .passwordChangedAt(user.getPasswordChangedAt())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }

    public String getFullName() {
        return firstName + " " + lastName;
    }

    public String getStatus() {
        if (!emailVerified) return "UNVERIFIED";
        if (!enabled) return "DISABLED";
        if (!accountNonLocked) return "LOCKED";
        return "ACTIVE";
    }
}