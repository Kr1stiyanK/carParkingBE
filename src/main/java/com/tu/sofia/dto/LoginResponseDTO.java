package com.tu.sofia.dto;

public class LoginResponseDTO {

    private String jwtToken;

    public LoginResponseDTO(String jwtToken) {
        this.jwtToken = jwtToken;
    }

    public String getJwtToken() {
        return jwtToken;
    }

    public LoginResponseDTO setJwtToken(String jwtToken) {
        this.jwtToken = jwtToken;
        return this;
    }
}
