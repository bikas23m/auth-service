package com.bikas.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Service for rate limiting and brute force protection
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RateLimitService {

    private final ConcurrentMap<String, AttemptInfo> attemptCache = new ConcurrentHashMap<>();

    @Value("${app.rate-limit.requests-per-minute:60}")
    private int requestsPerMinute;

    @Value("${app.security.max-login-attempts:5}")
    private int maxLoginAttempts;

    @Value("${app.security.account-lockout-duration:1800000}") // 30 minutes
    private long lockoutDuration;

    /**
     * Check if login attempt is allowed
     */
    public boolean allowLoginAttempt(String email) {
        String key = "login:" + email;
        AttemptInfo info = attemptCache.computeIfAbsent(key, k -> new AttemptInfo());

        synchronized (info) {
            long now = System.currentTimeMillis();

            // Reset if lockout period has passed
            if (info.isLocked() && now - info.getLastAttempt() > lockoutDuration) {
                info.reset();
            }

            // Check if account is locked
            if (info.isLocked()) {
                log.warn("Login attempt blocked for locked account: {}", email);
                return false;
            }

            // Check rate limiting (per minute)
            if (now - info.getLastAttempt() > 60000) { // 1 minute
                info.resetMinuteWindow();
            }

            if (info.getAttemptsInMinute() >= requestsPerMinute) {
                log.warn("Rate limit exceeded for email: {}", email);
                return false;
            }

            info.incrementMinuteAttempts();
            return true;
        }
    }

    /**
     * Record failed login attempt
     */
    public void recordFailedLoginAttempt(String email) {
        String key = "login:" + email;
        AttemptInfo info = attemptCache.computeIfAbsent(key, k -> new AttemptInfo());

        synchronized (info) {
            info.incrementFailedAttempts();
            info.setLastAttempt(System.currentTimeMillis());

            if (info.getFailedAttempts() >= maxLoginAttempts) {
                info.lock();
                log.warn("Account locked due to multiple failed login attempts: {}", email);
            }
        }
    }

    /**
     * Record successful login attempt
     */
    public void recordSuccessfulLoginAttempt(String email) {
        String key = "login:" + email;
        AttemptInfo info = attemptCache.get(key);
        if (info != null) {
            synchronized (info) {
                info.reset();
            }
        }
        log.info("Successful login recorded for: {}", email);
    }

    /**
     * Check if request is allowed for general API calls
     */
    public boolean allowRequest(String clientId) {
        String key = "api:" + clientId;
        AttemptInfo info = attemptCache.computeIfAbsent(key, k -> new AttemptInfo());

        synchronized (info) {
            long now = System.currentTimeMillis();

            // Reset minute window if needed
            if (now - info.getLastAttempt() > 60000) { // 1 minute
                info.resetMinuteWindow();
            }

            if (info.getAttemptsInMinute() >= requestsPerMinute) {
                return false;
            }

            info.incrementMinuteAttempts();
            info.setLastAttempt(now);
            return true;
        }
    }

    /**
     * Get remaining attempts for user
     */
    public int getRemainingAttempts(String email) {
        String key = "login:" + email;
        AttemptInfo info = attemptCache.get(key);
        if (info == null) {
            return maxLoginAttempts;
        }

        synchronized (info) {
            if (info.isLocked()) {
                return 0;
            }
            return Math.max(0, maxLoginAttempts - info.getFailedAttempts());
        }
    }

    /**
     * Get lockout time remaining
     */
    public long getLockoutTimeRemaining(String email) {
        String key = "login:" + email;
        AttemptInfo info = attemptCache.get(key);
        if (info == null || !info.isLocked()) {
            return 0;
        }

        synchronized (info) {
            long elapsed = System.currentTimeMillis() - info.getLastAttempt();
            return Math.max(0, lockoutDuration - elapsed);
        }
    }

    /**
     * Inner class to track attempt information
     */
    private static class AttemptInfo {
        private int failedAttempts = 0;
        private int attemptsInMinute = 0;
        private long lastAttempt = 0;
        private long minuteWindowStart = 0;
        private boolean locked = false;

        public void incrementFailedAttempts() {
            this.failedAttempts++;
        }

        public void incrementMinuteAttempts() {
            long now = System.currentTimeMillis();
            if (minuteWindowStart == 0) {
                minuteWindowStart = now;
            }
            this.attemptsInMinute++;
        }

        public void resetMinuteWindow() {
            this.attemptsInMinute = 0;
            this.minuteWindowStart = System.currentTimeMillis();
        }

        public void reset() {
            this.failedAttempts = 0;
            this.attemptsInMinute = 0;
            this.lastAttempt = 0;
            this.minuteWindowStart = 0;
            this.locked = false;
        }

        public void lock() {
            this.locked = true;
        }

        // Getters and setters
        public int getFailedAttempts() { return failedAttempts; }
        public int getAttemptsInMinute() { return attemptsInMinute; }
        public long getLastAttempt() { return lastAttempt; }
        public void setLastAttempt(long lastAttempt) { this.lastAttempt = lastAttempt; }
        public boolean isLocked() { return locked; }
    }
}