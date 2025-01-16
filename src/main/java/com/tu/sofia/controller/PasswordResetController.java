package com.tu.sofia.controller;

import com.tu.sofia.dto.ResetPasswordDTO;
import com.tu.sofia.model.PasswordResetTokenEntity;
import com.tu.sofia.model.UserEntity;
import com.tu.sofia.service.PasswordResetService;
import com.tu.sofia.service.UserEntityService;
import jakarta.mail.MessagingException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;
import java.util.Optional;

@RestController
@CrossOrigin(origins = "http://localhost:4200")
@RequestMapping("/api")
public class PasswordResetController {

    private PasswordResetService passwordResetService;

    private UserEntityService userEntityService;

    public PasswordResetController(PasswordResetService passwordResetService, UserEntityService userEntityService) {
        this.passwordResetService = passwordResetService;
        this.userEntityService = userEntityService;
    }


    @PostMapping("/forgotten-password")
    public ResponseEntity<String> validateEmailPasswordReset(@RequestBody String email) throws MessagingException, UnsupportedEncodingException {
        Optional<UserEntity> optionalUser = this.userEntityService.validateEmail(email);
        this.passwordResetService.createPasswordResetToken(optionalUser.orElseThrow(() -> new UsernameNotFoundException("User not found")));
        return ResponseEntity.ok("Password reset link sent to your email.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody ResetPasswordDTO request) {
        Optional<PasswordResetTokenEntity> passwordResetTokenEntity = this.passwordResetService.resetPasswordToken(request.getToken());
        if (passwordResetTokenEntity.isPresent()) {
            try {
                userEntityService.resetForgottenPassword(passwordResetTokenEntity.get().getUser(), request.getNewPassword());
                passwordResetService.deleteResetPasswordToken(passwordResetTokenEntity.get());
                return ResponseEntity.ok("Password reset successfully.");
            } catch (IllegalArgumentException ex) {
                return ResponseEntity.badRequest().body(ex.getMessage());
            }
        }
        return ResponseEntity.badRequest().body("Invalid or expired token.");
    }
}
