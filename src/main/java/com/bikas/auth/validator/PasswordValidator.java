package com.bikas.auth.validator;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.extern.slf4j.Slf4j;

import java.util.regex.Pattern;

/**
 * Password strength validator
 */
@Slf4j
public class PasswordValidator implements ConstraintValidator<ValidPassword, String> {

    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$"
    );

    private static final String[] COMMON_PASSWORDS = {
            "password", "123456", "123456789", "12345678", "12345",
            "1234567", "password123", "admin", "qwerty", "abc123",
            "letmein", "monkey", "1234567890", "dragon", "1234",
            "baseball", "iloveyou", "trustno1", "sunshine", "princess"
    };

    @Override
    public void initialize(ValidPassword constraintAnnotation) {
        // No initialization needed
    }

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null) {
            addConstraintViolation(context, "Password is required");
            return false;
        }

        // Length check
        if (password.length() < 8) {
            addConstraintViolation(context, "Password must be at least 8 characters long");
            return false;
        }

        if (password.length() > 100) {
            addConstraintViolation(context, "Password must not exceed 100 characters");
            return false;
        }

        // Pattern check
        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            addConstraintViolation(context,
                    "Password must contain at least one digit, one lowercase letter, " +
                            "one uppercase letter, and one special character");
            return false;
        }

        // Common password check
        if (isCommonPassword(password)) {
            addConstraintViolation(context, "Password is too common. Please choose a stronger password");
            return false;
        }

        return true;
    }

    private boolean isCommonPassword(String password) {
        String lowerPassword = password.toLowerCase();
        for (String common : COMMON_PASSWORDS) {
            if (lowerPassword.equals(common)) {
                return true;
            }
        }
        return false;
    }

    private void addConstraintViolation(ConstraintValidatorContext context, String message) {
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(message).addConstraintViolation();
    }
}
