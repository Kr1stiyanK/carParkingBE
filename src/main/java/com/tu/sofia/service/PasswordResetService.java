package com.tu.sofia.service;

import com.tu.sofia.model.PasswordResetTokenEntity;
import com.tu.sofia.model.UserEntity;
import com.tu.sofia.repositories.PasswordResetRepository;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class PasswordResetService {

    private static final String RESET_URL = "http://localhost:4200/reset-password?token=";

    private final PasswordResetRepository passwordResetRepository;

    private final JavaMailSender mailSender;

    public PasswordResetService(PasswordResetRepository passwordResetRepository, JavaMailSender mailSender) {
        this.passwordResetRepository = passwordResetRepository;
        this.mailSender = mailSender;
    }

    public void createPasswordResetToken(UserEntity user) {

        PasswordResetTokenEntity passwordResetTokenEntity = new PasswordResetTokenEntity()
                .setToken(UUID.randomUUID().toString())
                .setExpiryDate(LocalDateTime.now().plusMinutes(15))
                .setUser(user);

        passwordResetRepository.save(passwordResetTokenEntity);
        sendResetEmail(user.getEmail(), RESET_URL + passwordResetTokenEntity.getToken().toString());
    }

    public void deleteResetPasswordToken(PasswordResetTokenEntity passwordResetTokenEntity) {
        passwordResetRepository.delete(passwordResetTokenEntity);
    }


    public Optional<PasswordResetTokenEntity> resetPasswordToken(String token) {
        PasswordResetTokenEntity resetToken = passwordResetRepository.findByToken(token);
        if (resetToken == null || resetToken.isExpired()) {
            return Optional.empty();
        }
        return Optional.of(resetToken);
    }

    private void sendResetEmail(String email, String resetUrl) {

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("slendermanz764@gmail.com");
        message.setTo(email);
        message.setSubject("ParkWise, Reset Your Password");
        message.setText("You have requested to reset your password.\n" + "Click the link below to reset your password:\n" + resetUrl + "\nIgnore this email if you do remember your password, or you have not made this request.");
        mailSender.send(message);
    }
}
