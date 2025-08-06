package com.bikas.auth.utils;

import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.function.Function;

/**
 * JWT utility methods
 */
@Component
@Slf4j
public class JwtUtil {

    /**
     * Check if token is expired without validation
     */
    public static boolean isTokenExpiredQuick(String token) {
        try {
            final Date expiration = extractExpirationQuick(token);
            return expiration.before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * Extract expiration date without full validation
     */
    public static Date extractExpirationQuick(String token) {
        return extractClaimQuick(token, Claims::getExpiration);
    }

    /**
     * Extract claim without full validation (for utility purposes only)
     */
    public static <T> T extractClaimQuick(String token, Function<Claims, T> claimsResolver) {
        try {
            // This is for utility only - not for security validation
            String[] chunks = token.split("\\.");
            if (chunks.length != 3) {
                throw new IllegalArgumentException("Invalid JWT token format");
            }

            // Decode payload (this is just for utility, not security validation)
            byte[] payloadBytes = java.util.Base64.getUrlDecoder().decode(chunks[1]);
            String payload = new String(payloadBytes);

            // Parse JSON manually for basic claims (simplified)
            return extractBasicClaim(payload, claimsResolver);
        } catch (Exception e) {
            log.debug("Failed to extract claim from token: {}", e.getMessage());
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T extractBasicClaim(String payload, Function<Claims, T> claimsResolver) {
        // This is a simplified implementation for utility purposes
        // Real validation should always use JwtService
        try {
            if (payload.contains("\"exp\":")) {
                String expStr = payload.split("\"exp\":")[1].split(",")[0].trim();
                long exp = Long.parseLong(expStr) * 1000; // Convert to milliseconds
                Date expDate = new Date(exp);

                // This is a hack for utility purposes only
                if (claimsResolver.toString().contains("getExpiration")) {
                    return (T) expDate;
                }
            }
        } catch (Exception e) {
            log.debug("Failed to parse token payload: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Get token type from payload
     */
    public static String getTokenType(String token) {
        try {
            String[] chunks = token.split("\\.");
            if (chunks.length != 3) {
                return null;
            }

            byte[] payloadBytes = java.util.Base64.getUrlDecoder().decode(chunks[1]);
            String payload = new String(payloadBytes);

            if (payload.contains("\"type\":\"access\"")) {
                return "access";
            } else if (payload.contains("\"type\":\"refresh\"")) {
                return "refresh";
            }

            return "unknown";
        } catch (Exception e) {
            log.debug("Failed to extract token type: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Validate token format (basic structure check)
     */
    public static boolean hasValidFormat(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }

        String[] chunks = token.split("\\.");
        return chunks.length == 3;
    }

    /**
     * Get time until token expires in milliseconds
     */
    public static long getTimeUntilExpiration(String token) {
        try {
            Date expiration = extractExpirationQuick(token);
            if (expiration == null) {
                return 0;
            }
            return Math.max(0, expiration.getTime() - System.currentTimeMillis());
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * Check if token expires within given minutes
     */
    public static boolean expiresWithinMinutes(String token, int minutes) {
        long timeUntilExpiration = getTimeUntilExpiration(token);
        return timeUntilExpiration <= (minutes * 60 * 1000);
    }

    /**
     * Generate secure random string for tokens
     */
    public static String generateSecureRandomString(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder();
        java.security.SecureRandom random = new java.security.SecureRandom();

        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }

        return sb.toString();
    }
}
