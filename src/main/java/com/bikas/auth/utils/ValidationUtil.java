package com.bikas.auth.utils;

import com.bikas.auth.dto.request.ChangePasswordRequest;
import com.bikas.auth.dto.request.RegisterRequest;
import com.bikas.auth.dto.request.UserUpdateRequest;
import lombok.extern.slf4j.Slf4j;

import java.util.regex.Pattern;

/**
 * Validation utility methods
 */
@Slf4j
public class ValidationUtil {

    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$"
    );

    private static final Pattern NAME_PATTERN = Pattern.compile("^[a-zA-Z\\s]+$");

    /**
     * Validate password strength
     */
    public static void validatePassword(String password) {
        if (password == null || password.trim().isEmpty()) {
            throw new IllegalArgumentException("Password is required");
        }

        if (password.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }

        if (password.length() > 100) {
            throw new IllegalArgumentException("Password must not exceed 100 characters");
        }

        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            throw new IllegalArgumentException(
                    "Password must contain at least one digit, one lowercase letter, " +
                            "one uppercase letter, and one special character (@#$%^&+=)"
            );
        }

        if (isCommonPassword(password)) {
            throw new IllegalArgumentException("Password is too common. Please choose a stronger password.");
        }
    }

    /**
     * Validate name (first name or last name)
     */
    public static void validateName(String name, String fieldName) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException(fieldName + " is required");
        }

        if (name.length() < 2) {
            throw new IllegalArgumentException(fieldName + " must be at least 2 characters long");
        }

        if (name.length() > 50) {
            throw new IllegalArgumentException(fieldName + " must not exceed 50 characters");
        }

        if (!NAME_PATTERN.matcher(name).matches()) {
            throw new IllegalArgumentException(fieldName + " can only contain letters and spaces");
        }
    }

    /**
     * Validate register request
     */
    public static void validateRegisterRequest(RegisterRequest request) {
        validateName(request.getFirstName(), "First name");
        validateName(request.getLastName(), "Last name");
        EmailUtil.validateEmailOrThrow(request.getEmail());
        validatePassword(request.getPassword());

        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("Password confirmation does not match");
        }

        if (request.getAcceptTerms() == null || !request.getAcceptTerms()) {
            throw new IllegalArgumentException("You must accept the terms and conditions");
        }
    }

    /**
     * Validate user update request
     */
    public static void validateUserUpdateRequest(UserUpdateRequest request) {
        validateName(request.getFirstName(), "First name");
        validateName(request.getLastName(), "Last name");
    }

    /**
     * Validate change password request
     */
    public static void validateChangePasswordRequest(ChangePasswordRequest request) {
        if (request.getCurrentPassword() == null || request.getCurrentPassword().trim().isEmpty()) {
            throw new IllegalArgumentException("Current password is required");
        }

        validatePassword(request.getNewPassword());

        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("Password confirmation does not match");
        }

        if (request.getCurrentPassword().equals(request.getNewPassword())) {
            throw new IllegalArgumentException("New password must be different from current password");
        }
    }

    /**
     * Check if password is in common passwords list
     */
    private static boolean isCommonPassword(String password) {
        String[] commonPasswords = {
                "password", "123456", "123456789", "12345678", "12345",
                "1234567", "password123", "admin", "qwerty", "abc123",
                "letmein", "monkey", "1234567890", "dragon", "1234",
                "baseball", "iloveyou", "trustno1", "sunshine", "princess",
                "football", "charlie", "aa123456", "welcome", "login"
        };

        String lowerPassword = password.toLowerCase();
        for (String common : commonPasswords) {
            if (lowerPassword.equals(common)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Validate string length
     */
    public static void validateLength(String value, String fieldName, int minLength, int maxLength) {
        if (value == null) {
            throw new IllegalArgumentException(fieldName + " is required");
        }

        if (value.length() < minLength) {
            throw new IllegalArgumentException(fieldName + " must be at least " + minLength + " characters long");
        }

        if (value.length() > maxLength) {
            throw new IllegalArgumentException(fieldName + " must not exceed " + maxLength + " characters");
        }
    }

    /**
     * Validate that string is not null or empty
     */
    public static void validateNotEmpty(String value, String fieldName) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(fieldName + " is required");
        }
    }

    /**
     * Validate ID parameter
     */
    public static void validateId(Long id, String fieldName) {
        if (id == null) {
            throw new IllegalArgumentException(fieldName + " is required");
        }

        if (id <= 0) {
            throw new IllegalArgumentException(fieldName + " must be a positive number");
        }
    }

    /**
     * Sanitize string input
     */
    public static String sanitizeString(String input) {
        if (input == null) {
            return null;
        }

        return input.trim()
                .replaceAll("<", "&lt;")
                .replaceAll(">", "&gt;")
                .replaceAll("\"", "&quot;")
                .replaceAll("'", "&#x27;")
                .replaceAll("/", "&#x2F;");
    }

    /**
     * Validate enum value
     */
    public static <T extends Enum<T>> void validateEnum(String value, Class<T> enumClass, String fieldName) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(fieldName + " is required");
        }

        try {
            Enum.valueOf(enumClass, value.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(fieldName + " must be a valid value");
        }
    }
}