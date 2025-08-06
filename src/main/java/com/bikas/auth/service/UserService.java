package com.bikas.auth.service;

import com.bikas.auth.dto.request.ChangePasswordRequest;
import com.bikas.auth.dto.request.UserUpdateRequest;
import com.bikas.auth.dto.response.MessageResponse;
import com.bikas.auth.dto.response.SecurityActivityResponse;
import com.bikas.auth.dto.response.UserResponse;
import com.bikas.auth.model.SecurityAudit;
import com.bikas.auth.model.User;
import com.bikas.auth.repo.SecurityAuditRepository;
import com.bikas.auth.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Service for user profile management
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final SecurityAuditRepository securityAuditRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final RefreshTokenService refreshTokenService;

    /**
     * Get user profile
     */
    public UserResponse getUserProfile(String email) {
        log.info("Getting profile for user: {}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return UserResponse.fromUser(user);
    }

    /**
     * Update user profile
     */
    @Transactional
    public UserResponse updateUserProfile(String email, UserUpdateRequest request) {
        log.info("Updating profile for user: {}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Update user details
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());

        User updatedUser = userRepository.save(user);

        // Log profile update
        logSecurityEvent(email, SecurityAudit.SecurityEventType.ADMIN_ACTION,
                "Profile updated successfully", true);

        return UserResponse.fromUser(updatedUser);
    }

    /**
     * Change user password
     */
    @Transactional
    public MessageResponse changePassword(String email, ChangePasswordRequest request) {
        log.info("Changing password for user: {}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Validate current password
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new RuntimeException("Current password is incorrect");
        }

        // Check if new password is different from current
        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new RuntimeException("New password must be different from current password");
        }

        // Validate password confirmation
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new RuntimeException("Password confirmation does not match");
        }

        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(user);

        // Revoke all refresh tokens for security
        refreshTokenService.revokeAllUserRefreshTokens(email);

        // Send password changed notification
        emailService.sendPasswordChangedNotification(user.getEmail(), user.getFullName());

        // Log password change
        logSecurityEvent(email, SecurityAudit.SecurityEventType.PASSWORD_CHANGE,
                "Password changed successfully", true);

        return MessageResponse.builder()
                .message("Password changed successfully. Please log in again.")
                .success(true)
                .build();
    }

    /**
     * Get user security activity logs
     */
    public Page<SecurityActivityResponse> getUserSecurityLogs(String email, Pageable pageable) {
        log.info("Getting security logs for user: {}", email);

        Page<SecurityAudit> auditPage = securityAuditRepository.findByUserEmailOrderByTimestampDesc(email, pageable);

        return auditPage.map(SecurityActivityResponse::fromSecurityAudit);
    }

    /**
     * Delete user account
     */
    @Transactional
    public MessageResponse deleteUserAccount(String email) {
        log.info("Deleting account for user: {}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Revoke all refresh tokens
        refreshTokenService.revokeAllUserRefreshTokens(email);

        // Log account deletion
        logSecurityEvent(email, SecurityAudit.SecurityEventType.ADMIN_ACTION,
                "Account deleted by user", true);

        // Delete user
        userRepository.delete(user);

        return MessageResponse.builder()
                .message("Account deleted successfully")
                .success(true)
                .build();
    }

    /**
     * Check if user exists
     */
    public boolean userExists(String email) {
        return userRepository.existsByEmail(email);
    }

    /**
     * Get user by email
     */
    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found: " + email));
    }

    private void logSecurityEvent(String userEmail, SecurityAudit.SecurityEventType eventType,
                                  String description, boolean success) {
        SecurityAudit audit = SecurityAudit.builder()
                .userEmail(userEmail)
                .eventType(eventType)
                .eventDescription(description)
                .success(success)
                .build();

        securityAuditRepository.save(audit);
    }
}