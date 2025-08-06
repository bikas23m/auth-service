package com.bikas.auth.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Service for sending emails
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Value("${app.name}")
    private String appName;

    @Value("${app.base-url}")
    private String baseUrl;

    /**
     * Send email verification
     */
    @Async
    public void sendEmailVerification(String to, String name, String verificationLink) {
        String subject = "Verify Your Email Address - " + appName;
        String template = loadEmailTemplate("email-verification.html");

        String htmlContent = template
                .replace("{{name}}", name)
                .replace("{{appName}}", appName)
                .replace("{{verificationLink}}", verificationLink)
                .replace("{{baseUrl}}", baseUrl);

        sendHtmlEmail(to, subject, htmlContent);
    }

    /**
     * Send password reset email
     */
    @Async
    public void sendPasswordResetEmail(String to, String name, String resetLink) {
        String subject = "Password Reset Request - " + appName;
        String template = loadEmailTemplate("password-reset.html");

        String htmlContent = template
                .replace("{{name}}", name)
                .replace("{{appName}}", appName)
                .replace("{{resetLink}}", resetLink)
                .replace("{{baseUrl}}", baseUrl);

        sendHtmlEmail(to, subject, htmlContent);
    }

    /**
     * Send welcome email
     */
    @Async
    public void sendWelcomeEmail(String to, String name) {
        String subject = "Welcome to " + appName + "!";
        String htmlContent = generateWelcomeEmailContent(name);
        sendHtmlEmail(to, subject, htmlContent);
    }

    /**
     * Send account locked notification
     */
    @Async
    public void sendAccountLockedEmail(String to, String name, LocalDateTime unlockTime) {
        String subject = "Account Temporarily Locked - " + appName;
        String template = loadEmailTemplate("account-locked.html");

        String formattedUnlockTime = unlockTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        String htmlContent = template
                .replace("{{name}}", name)
                .replace("{{appName}}", appName)
                .replace("{{unlockTime}}", formattedUnlockTime)
                .replace("{{baseUrl}}", baseUrl);

        sendHtmlEmail(to, subject, htmlContent);
    }

    /**
     * Send password changed notification
     */
    @Async
    public void sendPasswordChangedNotification(String to, String name) {
        String subject = "Password Changed Successfully - " + appName;
        String htmlContent = generatePasswordChangedEmailContent(name);
        sendHtmlEmail(to, subject, htmlContent);
    }

    /**
     * Generic method to send HTML email
     */
    private void sendHtmlEmail(String to, String subject, String htmlContent) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail, appName);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Email sent successfully to: {}", to);

        } catch (MessagingException | UnsupportedEncodingException e) {
            log.error("Failed to send email to {}: {}", to, e.getMessage());
            throw new RuntimeException("Failed to send email", e);
        }
    }

    /**
     * Load email template from resources
     */
    private String loadEmailTemplate(String templateName) {
        try {
            return Files.readString(Paths.get("src/main/resources/templates/" + templateName));
        } catch (IOException e) {
            log.error("Failed to load email template: {}", templateName);
            return getDefaultEmailTemplate();
        }
    }

    /**
     * Generate welcome email content
     */
    private String generateWelcomeEmailContent(String name) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Welcome to %s</title>
            </head>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background-color: #f8f9fa; padding: 30px; border-radius: 10px;">
                    <h1 style="color: #333; text-align: center;">Welcome to %s!</h1>
                    <p>Dear %s,</p>
                    <p>Welcome to %s! Your account has been successfully verified and you can now enjoy all the features of our platform.</p>
                    <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
                    <p>Best regards,<br>The %s Team</p>
                </div>
            </body>
            </html>
            """.formatted(appName, appName, name, appName, appName);
    }

    /**
     * Generate password changed email content
     */
    private String generatePasswordChangedEmailContent(String name) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Password Changed - %s</title>
            </head>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background-color: #f8f9fa; padding: 30px; border-radius: 10px;">
                    <h1 style="color: #333; text-align: center;">Password Changed Successfully</h1>
                    <p>Dear %s,</p>
                    <p>Your password has been successfully changed. If you did not make this change, please contact our support team immediately.</p>
                    <p>For security reasons, all your active sessions have been terminated and you will need to log in again.</p>
                    <p>Best regards,<br>The %s Team</p>
                </div>
            </body>
            </html>
            """.formatted(appName, name, appName);
    }

    /**
     * Get default email template
     */
    private String getDefaultEmailTemplate() {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>{{appName}}</title>
            </head>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background-color: #f8f9fa; padding: 30px; border-radius: 10px;">
                    <h1 style="color: #333; text-align: center;">{{appName}}</h1>
                    <p>Dear {{name}},</p>
                    <p>Thank you for using {{appName}}.</p>
                    <p>Best regards,<br>The {{appName}} Team</p>
                </div>
            </body>
            </html>
            """;
    }
}