package com.tu.sofia.model;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "password_reset_tokens")
public class PasswordResetTokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String token;

    @OneToOne
    private UserEntity user;

    private LocalDateTime expiryDate;

    public Long getId() {
        return id;
    }

    public PasswordResetTokenEntity setId(Long id) {
        this.id = id;
        return this;
    }

    public String getToken() {
        return token;
    }

    public PasswordResetTokenEntity setToken(String token) {
        this.token = token;
        return this;
    }

    public UserEntity getUser() {
        return user;
    }

    public PasswordResetTokenEntity setUser(UserEntity user) {
        this.user = user;
        return this;
    }

    public LocalDateTime getExpiryDate() {
        return expiryDate;
    }

    public PasswordResetTokenEntity setExpiryDate(LocalDateTime expiryDate) {
        this.expiryDate = expiryDate;
        return this;
    }

    public boolean isExpired() {
        return expiryDate.isBefore(LocalDateTime.now());
    }
}
