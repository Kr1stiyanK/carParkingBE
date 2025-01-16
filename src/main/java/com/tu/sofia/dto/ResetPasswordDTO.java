package com.tu.sofia.dto;

public class ResetPasswordDTO {
    private String token;
    private String newPassword;


    public String getToken() {
        return token;
    }

    public ResetPasswordDTO setToken(String token) {
        this.token = token;
        return this;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public ResetPasswordDTO setNewPassword(String newPassword) {
        this.newPassword = newPassword;
        return this;
    }
}
