package com.bikas.auth.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * Security Audit entity for logging security-related activities.
 */
@Entity
@Table(name = "security_audit",
        indexes = {
                @Index(name = "idx_user_email", columnList = "user_email"),
                @Index(name = "idx_event_type", columnList = "event_type"),
                @Index(name = "idx_timestamp", columnList = "timestamp")
        })
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_email")
    private String userEmail;

    @Column(name = "event_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private SecurityEventType eventType;

    @Column(name = "event_description")
    private String eventDescription;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "success", nullable = false)
    private Boolean success;

    @CreationTimestamp
    @Column(name = "timestamp", nullable = false, updatable = false)
    private LocalDateTime timestamp;

    @Column(name = "additional_data", columnDefinition = "TEXT")
    private String additionalData;

    public enum SecurityEventType {
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        LOGOUT,
        REGISTRATION,
        PASSWORD_CHANGE,
        PASSWORD_RESET_REQUEST,
        PASSWORD_RESET_SUCCESS,
        EMAIL_VERIFICATION,
        ACCOUNT_LOCKED,
        ACCOUNT_UNLOCKED,
        TOKEN_REFRESH,
        SUSPICIOUS_ACTIVITY,
        ADMIN_ACTION
    }
}
