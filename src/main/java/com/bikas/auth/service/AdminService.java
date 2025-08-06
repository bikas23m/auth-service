package com.bikas.auth.service;

import com.bikas.auth.dto.request.UpdateUserRoleRequest;
import com.bikas.auth.dto.response.AdminUserResponse;
import com.bikas.auth.dto.response.MessageResponse;
import com.bikas.auth.dto.response.SecurityAuditResponse;
import com.bikas.auth.dto.response.SystemStatisticsResponse;
import com.bikas.auth.model.SecurityAudit;
import com.bikas.auth.model.User;
import com.bikas.auth.repo.SecurityAuditRepository;
import com.bikas.auth.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Service for admin user management operations
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AdminService {

    private final UserRepository userRepository;
    private final SecurityAuditRepository securityAuditRepository;
    private final RefreshTokenService refreshTokenService;

    /**
     * Get all users with pagination and search
     */
    public Page<AdminUserResponse> getAllUsers(String search, Pageable pageable) {
        log.info("Getting all users with search: {}", search);

        Page<User> userPage;
        if (search != null && !search.trim().isEmpty()) {
            userPage = userRepository.findBySearchTerm(search.trim(), pageable);
        } else {
            userPage = userRepository.findAll(pageable);
        }

        return userPage.map(AdminUserResponse::fromUser);
    }

    /**
     * Get user by ID
     */
    public AdminUserResponse getUserById(Long id) {
        log.info("Getting user by ID: {}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + id));

        return AdminUserResponse.fromUser(user);
    }

    /**
     * Block user account
     */
    @Transactional
    public MessageResponse blockUser(Long userId, String adminEmail) {
        log.info("Blocking user ID: {} by admin: {}", userId, adminEmail);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!user.getAccountNonLocked()) {
            return MessageResponse.builder()
                    .message("User account is already blocked")
                    .success(false)
                    .build();
        }

        // Block the account
        user.setAccountNonLocked(false);
        user.setAccountLockedUntil(null); // Permanent lock until admin unblocks
        userRepository.save(user);

        // Revoke all refresh tokens
        refreshTokenService.revokeAllUserRefreshTokens(user.getEmail());

        // Log admin action
        logSecurityEvent(user.getEmail(), SecurityAudit.SecurityEventType.ADMIN_ACTION,
                "Account blocked by admin: " + adminEmail, true);

        return MessageResponse.builder()
                .message("User account blocked successfully")
                .success(true)
                .build();
    }

    /**
     * Unblock user account
     */
    @Transactional
    public MessageResponse unblockUser(Long userId, String adminEmail) {
        log.info("Unblocking user ID: {} by admin: {}", userId, adminEmail);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.getAccountNonLocked()) {
            return MessageResponse.builder()
                    .message("User account is not blocked")
                    .success(false)
                    .build();
        }

        // Unblock the account
        user.setAccountNonLocked(true);
        user.setAccountLockedUntil(null);
        user.resetFailedLoginAttempts();
        userRepository.save(user);

        // Log admin action
        logSecurityEvent(user.getEmail(), SecurityAudit.SecurityEventType.ACCOUNT_UNLOCKED,
                "Account unblocked by admin: " + adminEmail, true);

        return MessageResponse.builder()
                .message("User account unblocked successfully")
                .success(true)
                .build();
    }

    /**
     * Update user role
     */
    @Transactional
    public MessageResponse updateUserRole(Long userId, UpdateUserRoleRequest request, String adminEmail) {
        log.info("Updating user role for ID: {} by admin: {}", userId, adminEmail);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Update roles
        user.setRoles(request.getRoles());
        userRepository.save(user);

        // Revoke all refresh tokens to force re-authentication with new roles
        refreshTokenService.revokeAllUserRefreshTokens(user.getEmail());

        // Log admin action
        String description = String.format("Role updated to %s by admin: %s. Reason: %s",
                request.getRoles(), adminEmail,
                request.getReason() != null ? request.getReason() : "Not specified");
        logSecurityEvent(user.getEmail(), SecurityAudit.SecurityEventType.ADMIN_ACTION, description, true);

        return MessageResponse.builder()
                .message("User role updated successfully")
                .success(true)
                .build();
    }

    /**
     * Delete user account
     */
    @Transactional
    public MessageResponse deleteUser(Long userId, String adminEmail) {
        log.info("Deleting user ID: {} by admin: {}", userId, adminEmail);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String userEmail = user.getEmail();

        // Revoke all refresh tokens
        refreshTokenService.revokeAllUserRefreshTokens(userEmail);

        // Log admin action before deletion
        logSecurityEvent(userEmail, SecurityAudit.SecurityEventType.ADMIN_ACTION,
                "Account deleted by admin: " + adminEmail, true);

        // Delete user
        userRepository.delete(user);

        return MessageResponse.builder()
                .message("User account deleted successfully")
                .success(true)
                .build();
    }

    /**
     * Get security audit logs
     */
    public Page<SecurityAuditResponse> getSecurityAuditLogs(String userEmail, String eventType, Pageable pageable) {
        log.info("Getting security audit logs");

        Page<SecurityAudit> auditPage;

        if (userEmail != null && !userEmail.trim().isEmpty()) {
            auditPage = securityAuditRepository.findByUserEmailOrderByTimestampDesc(userEmail.trim(), pageable);
        } else if (eventType != null && !eventType.trim().isEmpty()) {
            try {
                SecurityAudit.SecurityEventType eventTypeEnum = SecurityAudit.SecurityEventType.valueOf(eventType.trim().toUpperCase());
                auditPage = (Page<SecurityAudit>) securityAuditRepository.findByEventTypeAndTimestampAfter(
                        eventTypeEnum, LocalDateTime.now().minusDays(30));
            } catch (IllegalArgumentException e) {
                auditPage = securityAuditRepository.findAll(pageable);
            }
        } else {
            auditPage = securityAuditRepository.findAll(pageable);
        }

        return auditPage.map(SecurityAuditResponse::fromSecurityAudit);
    }

    /**
     * Get system statistics
     */
    public SystemStatisticsResponse getSystemStatistics() {
        log.info("Getting system statistics");

        LocalDateTime last30Days = LocalDateTime.now().minusDays(30);
        LocalDateTime last24Hours = LocalDateTime.now().minusHours(24);

        long totalUsers = userRepository.count();
        long activeUsers = userRepository.countActiveUsersSince(last30Days);
        long newUsers = userRepository.countUsersRegisteredSince(last30Days);

        // Count users by status
        long lockedUsers = userRepository.findAll().stream()
                .mapToLong(user -> !user.getAccountNonLocked() ? 1 : 0)
                .sum();

        long unverifiedUsers = userRepository.findAll().stream()
                .mapToLong(user -> !user.getEmailVerified() ? 1 : 0)
                .sum();

        // Count security events
        long totalLogins = securityAuditRepository.findByEventTypeAndTimestampAfter(
                SecurityAudit.SecurityEventType.LOGIN_SUCCESS, last30Days).size() +
                securityAuditRepository.findByEventTypeAndTimestampAfter(
                        SecurityAudit.SecurityEventType.LOGIN_FAILURE, last30Days).size();

        long successfulLogins = securityAuditRepository.findByEventTypeAndTimestampAfter(
                SecurityAudit.SecurityEventType.LOGIN_SUCCESS, last30Days).size();

        long failedLogins = securityAuditRepository.findByEventTypeAndTimestampAfter(
                SecurityAudit.SecurityEventType.LOGIN_FAILURE, last30Days).size();

        long passwordResets = securityAuditRepository.findByEventTypeAndTimestampAfter(
                SecurityAudit.SecurityEventType.PASSWORD_RESET_SUCCESS, last30Days).size();

        long emailVerifications = securityAuditRepository.findByEventTypeAndTimestampAfter(
                SecurityAudit.SecurityEventType.EMAIL_VERIFICATION, last30Days).size();

        long adminActions = securityAuditRepository.findByEventTypeAndTimestampAfter(
                SecurityAudit.SecurityEventType.ADMIN_ACTION, last30Days).size();

        return SystemStatisticsResponse.builder()
                .totalUsers(totalUsers)
                .activeUsers(activeUsers)
                .lockedUsers(lockedUsers)
                .unverifiedUsers(unverifiedUsers)
                .totalLogins(totalLogins)
                .successfulLogins(successfulLogins)
                .failedLogins(failedLogins)
                .passwordResets(passwordResets)
                .emailVerifications(emailVerifications)
                .adminActions(adminActions)
                .lastUpdated(LocalDateTime.now())
                .build();
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