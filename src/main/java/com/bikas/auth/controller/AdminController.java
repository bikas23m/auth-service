package com.bikas.auth.controller;

import com.bikas.auth.dto.request.UpdateUserRoleRequest;
import com.bikas.auth.dto.response.AdminUserResponse;
import com.bikas.auth.dto.response.MessageResponse;
import com.bikas.auth.dto.response.SecurityAuditResponse;
import com.bikas.auth.dto.response.SystemStatisticsResponse;
import com.bikas.auth.service.AdminService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * Admin controller for user management operations.
 */
@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Admin Management", description = "Admin user management APIs")
@SecurityRequirement(name = "bearerAuth")
public class AdminController {

    private final AdminService adminService;

    @Operation(summary = "Get all users", description = "Get paginated list of all users")
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public ResponseEntity<Page<AdminUserResponse>> getAllUsers(
            @RequestParam(required = false) String search,
            Pageable pageable) {
        log.info("Get all users request with search: {}", search);
        return ResponseEntity.ok(adminService.getAllUsers(search, pageable));
    }

    @Operation(summary = "Get user by ID", description = "Get user details by user ID")
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users/{id}")
    public ResponseEntity<AdminUserResponse> getUserById(@PathVariable Long id) {
        log.info("Get user by ID request: {}", id);
        return ResponseEntity.ok(adminService.getUserById(id));
    }

    @Operation(summary = "Block user account", description = "Block user account by ID")
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/users/{id}/block")
    public ResponseEntity<MessageResponse> blockUser(@PathVariable Long id, Authentication authentication) {
        log.info("Block user request for ID: {} by admin: {}", id, authentication.getName());
        return ResponseEntity.ok(adminService.blockUser(id, authentication.getName()));
    }

    @Operation(summary = "Unblock user account", description = "Unblock user account by ID")
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/users/{id}/unblock")
    public ResponseEntity<MessageResponse> unblockUser(@PathVariable Long id, Authentication authentication) {
        log.info("Unblock user request for ID: {} by admin: {}", id, authentication.getName());
        return ResponseEntity.ok(adminService.unblockUser(id, authentication.getName()));
    }

    @Operation(summary = "Update user role", description = "Update user role by ID")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @PutMapping("/users/{id}/role")
    public ResponseEntity<MessageResponse> updateUserRole(
            @PathVariable Long id,
            @Valid @RequestBody UpdateUserRoleRequest request,
            Authentication authentication) {
        log.info("Update user role request for ID: {} by admin: {}", id, authentication.getName());
        return ResponseEntity.ok(adminService.updateUserRole(id, request, authentication.getName()));
    }

    @Operation(summary = "Delete user account", description = "Delete user account by ID")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @DeleteMapping("/users/{id}")
    public ResponseEntity<MessageResponse> deleteUser(@PathVariable Long id, Authentication authentication) {
        log.info("Delete user request for ID: {} by admin: {}", id, authentication.getName());
        return ResponseEntity.ok(adminService.deleteUser(id, authentication.getName()));
    }

    @Operation(summary = "Get security audit logs", description = "Get system security audit logs")
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/security-audit")
    public ResponseEntity<Page<SecurityAuditResponse>> getSecurityAuditLogs(
            @RequestParam(required = false) String userEmail,
            @RequestParam(required = false) String eventType,
            Pageable pageable) {
        log.info("Get security audit logs request");
        return ResponseEntity.ok(adminService.getSecurityAuditLogs(userEmail, eventType, pageable));
    }

    @Operation(summary = "Get system statistics", description = "Get system usage statistics")
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/statistics")
    public ResponseEntity<SystemStatisticsResponse> getSystemStatistics() {
        log.info("Get system statistics request");
        return ResponseEntity.ok(adminService.getSystemStatistics());
    }
}
