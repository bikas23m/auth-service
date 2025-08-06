package com.bikas.auth.service;

import com.bikas.auth.model.BlacklistedToken;
import com.bikas.auth.repo.BlacklistedTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

/**
 * Service for managing blacklisted JWT tokens
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class BlacklistService {

    private final BlacklistedTokenRepository blacklistedTokenRepository;

    /**
     * Add token to blacklist
     */
    @Transactional
    public void blacklistToken(String token, long expirationTime, String userEmail) {
        try {

            LocalDateTime expiresAt = LocalDateTime.ofInstant(
                    Instant.ofEpochMilli(expirationTime),
                    ZoneId.systemDefault()
            );

            BlacklistedToken blacklistedToken = BlacklistedToken.builder()
                    .token(token)
                    .expiresAt(expiresAt)
                    .userEmail(userEmail)
                    .reason("User logout")
                    .build();

            blacklistedTokenRepository.save(blacklistedToken);
            log.info("Token blacklisted successfully for user: {}", userEmail);
        } catch (Exception e) {
            log.error("Failed to blacklist token: {}", e.getMessage());
            throw new RuntimeException("Failed to blacklist token", e);
        }
    }

    /**
     * Check if token is blacklisted
     */
    public boolean isTokenBlacklisted(String token) {
        return blacklistedTokenRepository.existsByToken(token);
    }

    /**
     * Cleanup expired blacklisted tokens
     * Runs every hour
     */
    @Scheduled(fixedRate = 3600000) // 1 hour
    @Transactional
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        int deletedCount = blacklistedTokenRepository.deleteExpiredTokens(now);
        if (deletedCount > 0) {
            log.info("Cleaned up {} expired blacklisted tokens", deletedCount);
        }
    }
}