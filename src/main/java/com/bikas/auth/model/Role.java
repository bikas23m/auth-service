package com.bikas.auth.model;

/**
 * User roles enumeration for role-based access control.
 */
public enum Role {
    /**
     * Regular user with basic permissions
     */
    USER,

    /**
     * Administrator with elevated permissions
     */
    ADMIN,

    /**
     * Super administrator with full system access
     */
    SUPER_ADMIN;

    /**
     * Get role display name
     */
    public String getDisplayName() {
        return switch (this) {
            case USER -> "User";
            case ADMIN -> "Administrator";
            case SUPER_ADMIN -> "Super Administrator";
        };
    }
}
