package com.tu.sofia.dto;

public class UpdateProfileDTO {

    private String currentEmail;
    private String newEmail;

    public String getCurrentEmail() {
        return currentEmail;
    }

    public UpdateProfileDTO setCurrentEmail(String currentEmail) {
        this.currentEmail = currentEmail;
        return this;
    }

    public String getNewEmail() {
        return newEmail;
    }

    public UpdateProfileDTO setNewEmail(String newEmail) {
        this.newEmail = newEmail;
        return this;
    }
}
