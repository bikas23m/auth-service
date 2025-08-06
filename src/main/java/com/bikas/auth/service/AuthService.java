package com.bikas.auth.service;

import com.bikas.auth.config.JwtConfig;
import com.bikas.auth.dto.request.*;
import com.bikas.auth.dto.response.JwtResponse;
import com.bikas.auth.dto.response.MessageResponse;
import com.bikas.auth.dto.response.UserResponse;
import com.bikas.auth.exception.InvalidTokenException;
import com.bikas.auth.exception.TokenRefreshException;
import com.bikas.auth.exception.UserAlreadyExistsException;
import com.bikas.auth.model.*;
import com.bikas.auth.repo.PasswordResetTokenRepository;
import com.bikas.auth.repo.RefreshTokenRepository;
import com.bikas.auth.repo.SecurityAuditRepository;
import com.bikas.auth.repo.UserRepository;
import com.bikas.auth.utils.ValidationUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.security.auth.login.AccountLockedException;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Authentication service handling user registration, login, logout, and token management.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final SecurityAuditRepository securityAuditRepository;

    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final BlacklistService blacklistService;
    private final EmailService emailService;
    private final RateLimitService rateLimitService;

    private final JwtConfig jwtConfig;

    @Value("${app.base-url}")
    private String baseUrl;

    @Value("${app.security.max-login-attempts}")
    private int maxLoginAttempts;

    @Value("${app.security.account-lockout-duration}")
    private int accountLockoutDuration;

    /**
     * Register a new user
     */
    @Transactional
    public MessageResponse register(RegisterRequest request) {
        log.info("Registering new user with email: {}", request.getEmail());

        // Check if user already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("User with email already exists: " + request.getEmail());
        }

        // Create new user
        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Set.of(Role.USER))
                .emailVerified(false)
                .enabled(true)
                .accountNonLocked(true)
                .emailVerificationToken(UUID.randomUUID().toString())
                .emailVerificationExpiresAt(LocalDateTime.now().plusHours(24))
                .build();

        userRepository.save(user);

        // Send verification email
        String verificationLink = baseUrl + "/api/auth/verify-email?token=" + user.getEmailVerificationToken();
        emailService.sendEmailVerification(user.getEmail(), user.getFullName(), verificationLink);

        // Log security event
        logSecurityEvent(user.getEmail(), SecurityAudit.SecurityEventType.REGISTRATION,
                "User registered successfully", true);

        return MessageResponse.builder()
                .message("Registration successful. Please check your email to verify your account.")
                .success(true)
                .build();
    }

    /**
     * Authenticate user and generate tokens
     */
    @Transactional
    public JwtResponse login(LoginRequest request) {
        log.info("Login attempt for email: {}", request.getEmail());

        // Check rate limiting
        if (!rateLimitService.allowLoginAttempt(request.getEmail())) {
            throw new RuntimeException("Too many login attempts. Please try again later.");
        }

        try {
            // Find user
            User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

            // Check if account is locked
            if (!user.isAccountNonLocked()) {
                throw new AccountLockedException("Account is locked due to multiple failed login attempts");
            }

            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );

            // Check if account is enabled and verified
            if (!user.isEnabled()) {
                throw new DisabledException("Account is not verified. Please check your email.");
            }

            // Reset failed login attempts on successful login
            if (user.getFailedLoginAttempts() > 0) {
                user.resetFailedLoginAttempts();
                userRepository.save(user);
            }

            // Update last login
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);

            // Generate tokens
            String accessToken = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            // Save refresh token
            refreshTokenService.createRefreshToken(user, refreshToken);

            // Log successful login
            logSecurityEvent(user.getEmail(), SecurityAudit.SecurityEventType.LOGIN_SUCCESS,
                    "User logged in successfully", true);

            return JwtResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(jwtConfig.getAccessTokenExpirationInSeconds())
                    .user(UserResponse.fromUser(user))
                    .build();

        } catch (BadCredentialsException | AccountLockedException e) {
            // Handle failed login attempt
            handleFailedLoginAttempt(request.getEmail());
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    /**
     * Refresh access token using refresh token
     */
    @Transactional
    public JwtResponse refreshToken(RefreshTokenRequest request) {
        log.info("Token refresh request");

        String refreshToken = request.getRefreshToken();


        String userEmail = jwtService.extractUsername(refreshToken);
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new TokenRefreshException("User not found"));

        // Validate refresh token
        if (!jwtService.validateRefreshToken(refreshToken, user)) {
            throw new TokenRefreshException("Invalid refresh token");
        }


        // Check if refresh token exists in database
        RefreshToken storedRefreshToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new TokenRefreshException("Refresh token not found"));

        if (storedRefreshToken.isExpired() || storedRefreshToken.getIsRevoked()) {
            throw new TokenRefreshException("Refresh token is expired or revoked");
        }

        // Generate new tokens
        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        // Revoke old refresh token and create new one
        refreshTokenService.revokeRefreshToken(storedRefreshToken);
        refreshTokenService.createRefreshToken(user, newRefreshToken);

        // Log token refresh
        logSecurityEvent(user.getEmail(), SecurityAudit.SecurityEventType.TOKEN_REFRESH,
                "Token refreshed successfully", true);

        return JwtResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtConfig.getAccessTokenExpirationInSeconds())
                .user(UserResponse.fromUser(user))
                .build();
    }

    /**
     * Logout user and blacklist token
     */
    @Transactional
    public MessageResponse logout(String authHeader) {
        log.info("Logout request");

        String token = jwtService.extractTokenFromHeader(authHeader);
        if (token == null) {
            throw new InvalidTokenException("Invalid authorization header");
        }

        try {
            String userEmail = jwtService.extractUsername(token);
            long expirationTime = jwtService.getTokenExpirationTime(token);
            // Blacklist the access token
            blacklistService.blacklistToken(token, expirationTime, userEmail);

            // Revoke refresh tokens for this user
            refreshTokenService.revokeAllUserRefreshTokens(userEmail);

            // Log logout event
            logSecurityEvent(userEmail, SecurityAudit.SecurityEventType.LOGOUT,
                    "User logged out successfully", true);

            return MessageResponse.builder()
                    .message("Logout successful")
                    .success(true)
                    .build();

        } catch (Exception e) {
            log.error("Error during logout: {}", e.getMessage());
            throw new RuntimeException("Logout failed");
        }
    }

    /**
     * Verify email address
     */
    @Transactional
    public MessageResponse verifyEmail(String token) {
        log.info("Email verification request");

        User user = userRepository.findByEmailVerificationToken(token)
                .orElseThrow(() -> new InvalidTokenException("Invalid verification token"));

        if (user.getEmailVerificationExpiresAt().isBefore(LocalDateTime.now())) {
            throw new InvalidTokenException("Verification token has expired");
        }

        if (user.getEmailVerified()) {
            return MessageResponse.builder()
                    .message("Email is already verified")
                    .success(true)
                    .build();
        }

        // Verify email
        user.setEmailVerified(true);
        user.setEmailVerificationToken(null);
        user.setEmailVerificationExpiresAt(null);
        userRepository.save(user);

        // Send welcome email
        emailService.sendWelcomeEmail(user.getEmail(), user.getFullName());

        // Log email verification
        logSecurityEvent(user.getEmail(), SecurityAudit.SecurityEventType.EMAIL_VERIFICATION,
                "Email verified successfully", true);

        return MessageResponse.builder()
                .message("Email verified successfully")
                .success(true)
                .build();
    }

    /**
     * Request password reset
     */
    @Transactional
    public MessageResponse forgotPassword(ForgotPasswordRequest request) {
        log.info("Password reset request for email: {}", request.getEmail());

        Optional<User> userOpt = userRepository.findByEmail(request.getEmail());

        // Always return success message for security reasons
        if (userOpt.isEmpty()) {
            log.warn("Password reset requested for non-existent email: {}", request.getEmail());
            return MessageResponse.builder()
                    .message("If the email exists, you will receive password reset instructions")
                    .success(true)
                    .build();
        }

        User user = userOpt.get();

        // Create password reset token
        PasswordResetToken resetToken = PasswordResetToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .expiresAt(LocalDateTime.now().plusHours(1))
                .build();

        passwordResetTokenRepository.save(resetToken);

        // Send password reset email
        String resetLink = baseUrl + "/api/auth/reset-password?token=" + resetToken.getToken();
        emailService.sendPasswordResetEmail(user.getEmail(), user.getFullName(), resetLink);

        // Log password reset request
        logSecurityEvent(user.getEmail(), SecurityAudit.SecurityEventType.PASSWORD_RESET_REQUEST,
                "Password reset requested", true);

        return MessageResponse.builder()
                .message("If the email exists, you will receive password reset instructions")
                .success(true)
                .build();
    }

    /**
     * Reset password using reset token
     */
    @Transactional
    public MessageResponse resetPassword(PasswordResetRequest request) {
        log.info("Password reset with token");

        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(request.getToken())
                .orElseThrow(() -> new InvalidTokenException("Invalid reset token"));

        if (!resetToken.isValid()) {
            throw new InvalidTokenException("Reset token is expired or already used");
        }

        // Validate new password
        ValidationUtil.validatePassword(request.getNewPassword());

        User user = resetToken.getUser();

        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(user);

        // Mark token as used
        resetToken.markAsUsed();
        passwordResetTokenRepository.save(resetToken);

        // Revoke all refresh tokens for security
        refreshTokenService.revokeAllUserRefreshTokens(user.getEmail());

        // Log password reset success
        logSecurityEvent(user.getEmail(), SecurityAudit.SecurityEventType.PASSWORD_RESET_SUCCESS,
                "Password reset successfully", true);

        return MessageResponse.builder()
                .message("Password reset successfully")
                .success(true)
                .build();
    }

    /**
     * Resend email verification
     */
    @Transactional
    public MessageResponse resendEmailVerification(String email) {
        log.info("Resend email verification for: {}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.getEmailVerified()) {
            return MessageResponse.builder()
                    .message("Email is already verified")
                    .success(true)
                    .build();
        }

        // Generate new verification token
        user.setEmailVerificationToken(UUID.randomUUID().toString());
        user.setEmailVerificationExpiresAt(LocalDateTime.now().plusHours(24));
        userRepository.save(user);

        // Send verification email
        String verificationLink = baseUrl + "/api/auth/verify-email?token=" + user.getEmailVerificationToken();
        emailService.sendEmailVerification(user.getEmail(), user.getFullName(), verificationLink);

        return MessageResponse.builder()
                .message("Verification email sent")
                .success(true)
                .build();
    }

    private void handleFailedLoginAttempt(String email) {
        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            user.incrementFailedLoginAttempts();

            if (user.getFailedLoginAttempts() >= maxLoginAttempts) {
                user.lockAccount(accountLockoutDuration / 60000); // Convert to minutes

                // Send account locked email
                emailService.sendAccountLockedEmail(user.getEmail(), user.getFullName(),
                        LocalDateTime.now().plusMinutes(accountLockoutDuration / 60000));

                // Log account locked event
                logSecurityEvent(email, SecurityAudit.SecurityEventType.ACCOUNT_LOCKED,
                        "Account locked due to multiple failed login attempts", true);
            }

            userRepository.save(user);
        }

        // Log failed login attempt
        logSecurityEvent(email, SecurityAudit.SecurityEventType.LOGIN_FAILURE,
                "Invalid credentials provided", false);
    }

    private void logSecurityEvent(String userEmail, SecurityAudit.SecurityEventType eventType,
                                  String description, boolean success) {
        SecurityAudit audit = SecurityAudit.builder()
                .userEmail(userEmail)
                .eventType(eventType)
                .eventDescription(description)
                .success(success)
                .build();

        securityAuditRepository.save(audit);
    }
}
