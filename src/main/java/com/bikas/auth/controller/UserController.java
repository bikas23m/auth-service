package com.bikas.auth.controller;

import com.bikas.auth.dto.request.ChangePasswordRequest;
import com.bikas.auth.dto.request.UserUpdateRequest;
import com.bikas.auth.dto.response.MessageResponse;
import com.bikas.auth.dto.response.SecurityActivityResponse;
import com.bikas.auth.dto.response.UserResponse;
import com.bikas.auth.service.UserService;
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
 * User controller for user profile management.
 */
@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Management", description = "User profile management APIs")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    private final UserService userService;

    @Operation(summary = "Get user profile", description = "Get current user's profile information")
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/profile")
    public ResponseEntity<UserResponse> getProfile(Authentication authentication) {
        log.info("Get profile request for user: {}", authentication.getName());
        return ResponseEntity.ok(userService.getUserProfile(authentication.getName()));
    }

    @Operation(summary = "Update user profile", description = "Update current user's profile information")
    @PreAuthorize("hasRole('USER')")
    @PutMapping("/profile")
    public ResponseEntity<UserResponse> updateProfile(
            @Valid @RequestBody UserUpdateRequest request,
            Authentication authentication) {
        log.info("Update profile request for user: {}", authentication.getName());
        return ResponseEntity.ok(userService.updateUserProfile(authentication.getName(), request));
    }

    @Operation(summary = "Change password", description = "Change current user's password")
    @PreAuthorize("hasRole('USER')")
    @PutMapping("/change-password")
    public ResponseEntity<MessageResponse> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            Authentication authentication) {
        log.info("Change password request for user: {}", authentication.getName());
        return ResponseEntity.ok(userService.changePassword(authentication.getName(), request));
    }

    @Operation(summary = "Get security activity logs", description = "Get user's security activity history")
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/security-logs")
    public ResponseEntity<Page<SecurityActivityResponse>> getSecurityLogs(
            Authentication authentication, Pageable pageable) {
        log.info("Get security logs request for user: {}", authentication.getName());
        return ResponseEntity.ok(userService.getUserSecurityLogs(authentication.getName(), pageable));
    }

    @Operation(summary = "Delete user account", description = "Delete current user's account")
    @PreAuthorize("hasRole('USER')")
    @DeleteMapping("/account")
    public ResponseEntity<MessageResponse> deleteAccount(Authentication authentication) {
        log.info("Delete account request for user: {}", authentication.getName());
        return ResponseEntity.ok(userService.deleteUserAccount(authentication.getName()));
    }
}

