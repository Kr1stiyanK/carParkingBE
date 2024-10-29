package com.tu.sofia.dto;

public class ChangePasswordDTO {

    private String email;
    private String currentPassword;
    private String newPassword;

    public String getEmail() {
        return email;
    }

    public ChangePasswordDTO setEmail(String email) {
        this.email = email;
        return this;
    }

    public String getCurrentPassword() {
        return currentPassword;
    }

    public ChangePasswordDTO setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
        return this;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public ChangePasswordDTO setNewPassword(String newPassword) {
        this.newPassword = newPassword;
        return this;
    }
}
