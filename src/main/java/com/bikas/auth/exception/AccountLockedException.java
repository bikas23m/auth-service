package com.bikas.auth.exception;

import org.springframework.security.authentication.AccountStatusException;

/**
 * Exception thrown when account is locked
 */
public class AccountLockedException extends AccountStatusException {

    public AccountLockedException(String message) {
        super(message);
    }

    public AccountLockedException(String message, Throwable cause) {
        super(message, cause);
    }
}
