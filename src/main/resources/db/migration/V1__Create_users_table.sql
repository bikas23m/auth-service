-- Create users table
CREATE TABLE users (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    account_non_locked BOOLEAN NOT NULL DEFAULT TRUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_attempts INT DEFAULT 0,
    account_locked_until TIMESTAMP NULL,
    last_login TIMESTAMP NULL,
    password_changed_at TIMESTAMP NULL,
    email_verification_token VARCHAR(255) NULL,
    email_verification_expires_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_email_verified (email_verified),
    INDEX idx_account_non_locked (account_non_locked),
    INDEX idx_enabled (enabled),
    INDEX idx_email_verification_token (email_verification_token),
    INDEX idx_created_at (created_at)
);

-- Create user_roles table
CREATE TABLE user_roles (
    user_id BIGINT NOT NULL,
    role VARCHAR(20) NOT NULL,
    PRIMARY KEY (user_id, role),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_role (role)
);

-- Insert default admin user (password: Admin123!)
INSERT INTO users (
    first_name,
    last_name,
    email,
    password,
    email_verified,
    account_non_locked,
    enabled,
    created_at,
    updated_at
) VALUES (
    'System',
    'Administrator',
    'admin@jwtapp.com',
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqcsdQeO3rDG/0QqCGOdPY2', -- Admin123!
    TRUE,
    TRUE,
    TRUE,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Assign SUPER_ADMIN role to default admin
INSERT INTO user_roles (user_id, role)
SELECT id, 'SUPER_ADMIN' FROM users WHERE email = 'admin@jwtapp.com';

-- Add some sample users for testing
INSERT INTO users (
    first_name,
    last_name,
    email,
    password,
    email_verified,
    account_non_locked,
    enabled,
    created_at,
    updated_at
) VALUES
(
    'John',
    'Doe',
    'john.doe@example.com',
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqcsdQeO3rDG/0QqCGOdPY2', -- Admin123!
    TRUE,
    TRUE,
    TRUE,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
),
(
    'Jane',
    'Smith',
    'jane.smith@example.com',
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqcsdQeO3rDG/0QqCGOdPY2', -- Admin123!
    TRUE,
    TRUE,
    TRUE,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Assign roles to sample users
INSERT INTO user_roles (user_id, role)
SELECT id, 'USER' FROM users WHERE email = 'john.doe@example.com';

INSERT INTO user_roles (user_id, role)
SELECT id, 'ADMIN' FROM users WHERE email = 'jane.smith@example.com';