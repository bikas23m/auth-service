package com.bikas.auth.repo;

import com.bikas.auth.model.SecurityAudit;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface SecurityAuditRepository extends JpaRepository<SecurityAudit, Long> {

    Page<SecurityAudit> findByUserEmailOrderByTimestampDesc(String userEmail, Pageable pageable);

    @Query("SELECT sa FROM SecurityAudit sa WHERE sa.eventType = :eventType AND sa.timestamp >= :since")
    List<SecurityAudit> findByEventTypeAndTimestampAfter(
            @Param("eventType") SecurityAudit.SecurityEventType eventType,
            @Param("since") LocalDateTime since);

    @Query("SELECT sa FROM SecurityAudit sa WHERE sa.success = false AND sa.timestamp >= :since")
    List<SecurityAudit> findFailedEventsSince(@Param("since") LocalDateTime since);

    @Query("SELECT COUNT(sa) FROM SecurityAudit sa WHERE sa.userEmail = :email AND " +
            "sa.eventType = 'LOGIN_FAILURE' AND sa.timestamp >= :since")
    long countFailedLoginAttempts(@Param("email") String email, @Param("since") LocalDateTime since);
}
