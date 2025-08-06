package com.bikas.auth.dto.response;

import com.bikas.auth.model.SecurityAudit;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Security audit response DTO
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityAuditResponse {

    private Long id;
    private String userEmail;
    private String eventType;
    private String eventDescription;
    private String ipAddress;
    private String userAgent;
    private Boolean success;
    private LocalDateTime timestamp;
    private String additionalData;

    public static SecurityAuditResponse fromSecurityAudit(SecurityAudit audit) {
        return SecurityAuditResponse.builder()
                .id(audit.getId())
                .userEmail(audit.getUserEmail())
                .eventType(audit.getEventType().name())
                .eventDescription(audit.getEventDescription())
                .ipAddress(audit.getIpAddress())
                .userAgent(audit.getUserAgent())
                .success(audit.getSuccess())
                .timestamp(audit.getTimestamp())
                .additionalData(audit.getAdditionalData())
                .build();
    }
}
