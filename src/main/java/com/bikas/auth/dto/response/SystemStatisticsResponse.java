package com.bikas.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * System statistics response DTO
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SystemStatisticsResponse {

    private Long totalUsers;
    private Long activeUsers;
    private Long lockedUsers;
    private Long unverifiedUsers;
    private Long totalLogins;
    private Long failedLogins;
    private Long successfulLogins;
    private Long passwordResets;
    private Long emailVerifications;
    private Long adminActions;
    private LocalDateTime lastUpdated;

    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();
}
