package com.bikas.auth.validator;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.extern.slf4j.Slf4j;

import java.util.regex.Pattern;

/**
 * Email format validator with disposable email check
 */
@Slf4j
public class EmailValidator implements ConstraintValidator<ValidEmail, String> {

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@" +
                    "(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$"
    );

    private static final String[] DISPOSABLE_DOMAINS = {
            "10minutemail.com", "tempmail.org", "guerrillamail.com",
            "mailinator.com", "throwaway.email", "temp-mail.org",
            "getnada.com", "maildrop.cc", "yopmail.com", "sharklasers.com"
    };

    private boolean allowDisposable;

    @Override
    public void initialize(ValidEmail constraintAnnotation) {
        this.allowDisposable = constraintAnnotation.allowDisposable();
    }

    @Override
    public boolean isValid(String email, ConstraintValidatorContext context) {
        if (email == null || email.trim().isEmpty()) {
            addConstraintViolation(context, "Email is required");
            return false;
        }

        email = email.trim().toLowerCase();

        // Format validation
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            addConstraintViolation(context, "Invalid email format");
            return false;
        }

        // Disposable email check
        if (!allowDisposable && isDisposableEmail(email)) {
            addConstraintViolation(context, "Disposable email addresses are not allowed");
            return false;
        }

        // Length check
        if (email.length() > 254) {
            addConstraintViolation(context, "Email address is too long");
            return false;
        }

        return true;
    }

    private boolean isDisposableEmail(String email) {
        String domain = extractDomain(email);
        if (domain == null) {
            return false;
        }

        for (String disposable : DISPOSABLE_DOMAINS) {
            if (domain.equalsIgnoreCase(disposable)) {
                return true;
            }
        }

        return false;
    }

    private String extractDomain(String email) {
        String[] parts = email.split("@");
        return parts.length == 2 ? parts[1] : null;
    }

    private void addConstraintViolation(ConstraintValidatorContext context, String message) {
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(message).addConstraintViolation();
    }
}

