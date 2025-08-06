package com.bikas.auth.service;

import com.bikas.auth.config.JwtConfig;
import com.bikas.auth.model.RefreshToken;
import com.bikas.auth.model.User;
import com.bikas.auth.repo.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Service for managing refresh tokens
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtConfig jwtConfig;

    /**
     * Create refresh token for user
     */
    @Transactional
    public RefreshToken createRefreshToken(User user, String token) {
        log.info("Creating refresh token for user: {}", user.getEmail());

        // Revoke existing refresh tokens for the user
        revokeAllUserRefreshTokens(user.getEmail());

        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .user(user)
                .expiresAt(LocalDateTime.now().plusSeconds(jwtConfig.getRefreshTokenExpirationInSeconds()))
                .isRevoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }
    /**
     * Revoke refresh token
     */
    @Transactional
    public void revokeRefreshToken(RefreshToken refreshToken) {
        log.info("Revoking refresh token for user: {}", refreshToken.getUser().getEmail());
        refreshToken.revoke();
        refreshTokenRepository.save(refreshToken);
    }

    /**
     * Revoke all refresh tokens for user
     */
    @Transactional
    public void revokeAllUserRefreshTokens(String userEmail) {
        log.info("Revoking all refresh tokens for user: {}", userEmail);
        refreshTokenRepository.revokeAllTokensByUserEmail(userEmail, LocalDateTime.now());
    }

    /**
     * Get active refresh tokens for user
     */
    public List<RefreshToken> getActiveTokensByUserEmail(String userEmail) {
        return refreshTokenRepository.findActiveTokensByUserEmail(userEmail);
    }

    /**
     * Cleanup expired and revoked tokens
     * Runs every 6 hours
     */
    @Scheduled(fixedRate = 21600000) // 6 hours
    @Transactional
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        int deletedCount = refreshTokenRepository.deleteExpiredAndRevokedTokens(now);
        if (deletedCount > 0) {
            log.info("Cleaned up {} expired and revoked refresh tokens", deletedCount);
        }
    }
}