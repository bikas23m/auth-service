-- Create refresh_tokens table
CREATE TABLE refresh_tokens (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    token VARCHAR(512) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    user_id BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at),
    INDEX idx_is_revoked (is_revoked),
    INDEX idx_created_at (created_at)
);

-- Create blacklisted_tokens table
CREATE TABLE blacklisted_tokens (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    token VARCHAR(512) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    blacklisted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_email VARCHAR(255) NULL,
    reason VARCHAR(255) NULL,
    INDEX idx_token (token),
    INDEX idx_expires_at (expires_at),
    INDEX idx_user_email (user_email),
    INDEX idx_blacklisted_at (blacklisted_at)
);

-- Create password_reset_tokens table
CREATE TABLE password_reset_tokens (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    user_id BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at),
    INDEX idx_used (used),
    INDEX idx_created_at (created_at)
);

-- Create stored procedure to cleanup expired tokens
DELIMITER //

CREATE PROCEDURE CleanupExpiredTokens()
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE cleanup_count INT DEFAULT 0;

    -- Start transaction
    START TRANSACTION;

    -- Cleanup expired refresh tokens
    DELETE FROM refresh_tokens
    WHERE expires_at < NOW() OR is_revoked = TRUE;
    SET cleanup_count = cleanup_count + ROW_COUNT();

    -- Cleanup expired blacklisted tokens
    DELETE FROM blacklisted_tokens
    WHERE expires_at < NOW();
    SET cleanup_count = cleanup_count + ROW_COUNT();

    -- Cleanup expired password reset tokens
    DELETE FROM password_reset_tokens
    WHERE expires_at < NOW() OR used = TRUE;
    SET cleanup_count = cleanup_count + ROW_COUNT();

    -- Commit transaction
    COMMIT;

    -- Log cleanup results
    SELECT CONCAT('Cleaned up ', cleanup_count, ' expired tokens') AS result;

END //

DELIMITER ;

-- Create event to run cleanup every hour
CREATE EVENT IF NOT EXISTS cleanup_expired_tokens
ON SCHEDULE EVERY 1 HOUR
STARTS CURRENT_TIMESTAMP
DO
  CALL CleanupExpiredTokens();