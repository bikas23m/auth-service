package com.bikas.auth.utils;

import lombok.extern.slf4j.Slf4j;

import java.util.regex.Pattern;

/**
 * Email utility methods
 */
@Slf4j
public class EmailUtil {

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@" +
                    "(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$"
    );

    /**
     * Validate email format
     */
    public static boolean isValidEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            return false;
        }
        return EMAIL_PATTERN.matcher(email.trim()).matches();
    }

    /**
     * Normalize email address
     */
    public static String normalizeEmail(String email) {
        if (email == null) {
            return null;
        }
        return email.trim().toLowerCase();
    }

    /**
     * Mask email for privacy (e.g., j***@example.com)
     */
    public static String maskEmail(String email) {
        if (email == null || !isValidEmail(email)) {
            return email;
        }

        String[] parts = email.split("@");
        if (parts.length != 2) {
            return email;
        }

        String localPart = parts[0];
        String domainPart = parts[1];

        if (localPart.length() <= 2) {
            return email; // Don't mask very short emails
        }

        String maskedLocal = localPart.charAt(0) + "***" + localPart.charAt(localPart.length() - 1);
        return maskedLocal + "@" + domainPart;
    }

    /**
     * Extract domain from email
     */
    public static String extractDomain(String email) {
        if (email == null || !isValidEmail(email)) {
            return null;
        }

        String[] parts = email.split("@");
        return parts.length == 2 ? parts[1] : null;
    }

    /**
     * Check if email is from a disposable email provider
     */
    public static boolean isDisposableEmail(String email) {
        if (email == null) {
            return false;
        }

        String domain = extractDomain(email);
        if (domain == null) {
            return false;
        }

        // Common disposable email domains
        String[] disposableDomains = {
                "10minutemail.com", "tempmail.org", "guerrillamail.com",
                "mailinator.com", "throwaway.email", "temp-mail.org",
                "getnada.com", "maildrop.cc", "yopmail.com"
        };

        for (String disposable : disposableDomains) {
            if (domain.equalsIgnoreCase(disposable)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate email verification subject
     */
    public static String generateVerificationSubject(String appName) {
        return String.format("Verify Your Email Address - %s", appName);
    }

    /**
     * Generate password reset subject
     */
    public static String generatePasswordResetSubject(String appName) {
        return String.format("Password Reset Request - %s", appName);
    }

    /**
     * Generate welcome subject
     */
    public static String generateWelcomeSubject(String appName) {
        return String.format("Welcome to %s!", appName);
    }

    /**
     * Generate account locked subject
     */
    public static String generateAccountLockedSubject(String appName) {
        return String.format("Account Temporarily Locked - %s", appName);
    }

    /**
     * Validate email and throw exception if invalid
     */
    public static void validateEmailOrThrow(String email) {
        if (!isValidEmail(email)) {
            throw new IllegalArgumentException("Invalid email format: " + email);
        }

        if (isDisposableEmail(email)) {
            throw new IllegalArgumentException("Disposable email addresses are not allowed");
        }
    }

    /**
     * Check if email is from a corporate domain
     */
    public static boolean isCorporateEmail(String email) {
        if (email == null) {
            return false;
        }

        String domain = extractDomain(email);
        if (domain == null) {
            return false;
        }

        // Common personal email domains
        String[] personalDomains = {
                "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
                "aol.com", "icloud.com", "protonmail.com", "yandex.com"
        };

        for (String personal : personalDomains) {
            if (domain.equalsIgnoreCase(personal)) {
                return false;
            }
        }

        return true; // Assume corporate if not in personal list
    }
}