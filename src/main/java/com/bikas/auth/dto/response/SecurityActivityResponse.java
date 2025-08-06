package com.bikas.auth.dto.response;

import com.bikas.auth.model.SecurityAudit;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Security activity response DTO
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityActivityResponse {

    private Long id;
    private String eventType;
    private String eventDescription;
    private String ipAddress;
    private String userAgent;
    private Boolean success;
    private LocalDateTime timestamp;

    public static SecurityActivityResponse fromSecurityAudit(SecurityAudit audit) {
        return SecurityActivityResponse.builder()
                .id(audit.getId())
                .eventType(audit.getEventType().name())
                .eventDescription(audit.getEventDescription())
                .ipAddress(audit.getIpAddress())
                .userAgent(audit.getUserAgent())
                .success(audit.getSuccess())
                .timestamp(audit.getTimestamp())
                .build();
    }
}