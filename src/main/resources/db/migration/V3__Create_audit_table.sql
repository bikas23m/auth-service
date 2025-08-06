-- Create security_audit table
CREATE TABLE security_audit (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_email VARCHAR(255) NULL,
    event_type VARCHAR(50) NOT NULL,
    event_description TEXT NULL,
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,
    success BOOLEAN NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    additional_data TEXT NULL,
    INDEX idx_user_email (user_email),
    INDEX idx_event_type (event_type),
    INDEX idx_timestamp (timestamp),
    INDEX idx_success (success),
    INDEX idx_user_email_timestamp (user_email, timestamp),
    INDEX idx_event_type_timestamp (event_type, timestamp)
);

-- Create table for storing application configuration
CREATE TABLE app_config (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    config_key VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT NOT NULL,
    description TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_config_key (config_key)
);

-- Insert default configuration values
INSERT INTO app_config (config_key, config_value, description) VALUES
('max_login_attempts', '5', 'Maximum number of failed login attempts before account lockout'),
('account_lockout_duration', '1800000', 'Account lockout duration in milliseconds (30 minutes)'),
('jwt_access_token_expiration', '900000', 'JWT access token expiration in milliseconds (15 minutes)'),
('jwt_refresh_token_expiration', '86400000', 'JWT refresh token expiration in milliseconds (24 hours)'),
('email_verification_expiration', '86400000', 'Email verification token expiration in milliseconds (24 hours)'),
('password_reset_expiration', '3600000', 'Password reset token expiration in milliseconds (1 hour)'),
('rate_limit_requests_per_minute', '60', 'Maximum requests per minute per user'),
('session_timeout', '3600000', 'Session timeout in milliseconds (1 hour)');

-- Create stored procedure for security audit cleanup
DELIMITER //

CREATE PROCEDURE CleanupSecurityAudit()
BEGIN
    DECLARE cleanup_count INT DEFAULT 0;

    -- Keep only last 90 days of audit logs
    DELETE FROM security_audit
    WHERE timestamp < DATE_SUB(NOW(), INTERVAL 90 DAY);

    SET cleanup_count = ROW_COUNT();

    -- Log cleanup results
    SELECT CONCAT('Cleaned up ', cleanup_count, ' old security audit records') AS result;

END //

DELIMITER ;

-- Create event to run audit cleanup daily
CREATE EVENT IF NOT EXISTS cleanup_security_audit
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO
  CALL CleanupSecurityAudit();

-- Create view for recent security events
CREATE VIEW recent_security_events AS
SELECT
    id,
    user_email,
    event_type,
    event_description,
    ip_address,
    success,
    timestamp
FROM security_audit
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
ORDER BY timestamp DESC;

-- Create view for failed login attempts
CREATE VIEW failed_login_attempts AS
SELECT
    user_email,
    COUNT(*) as attempt_count,
    MAX(timestamp) as last_attempt,
    MIN(timestamp) as first_attempt
FROM security_audit
WHERE event_type = 'LOGIN_FAILURE'
    AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
GROUP BY user_email
HAVING attempt_count >= 3
ORDER BY attempt_count DESC;

-- Insert initial audit log
INSERT INTO security_audit (user_email, event_type, event_description, success)
VALUES ('system', 'SYSTEM_START', 'Database migration completed successfully', TRUE);