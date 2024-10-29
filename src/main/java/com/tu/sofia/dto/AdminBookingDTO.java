package com.tu.sofia.dto;

public class AdminBookingDTO {
    private String date;
    private String startTime;
    private String endTime;
    private int duration;
    private double amount;
    private String username;

    public String getDate() {
        return date;
    }

    public AdminBookingDTO setDate(String date) {
        this.date = date;
        return this;
    }

    public String getStartTime() {
        return startTime;
    }

    public AdminBookingDTO setStartTime(String startTime) {
        this.startTime = startTime;
        return this;
    }

    public String getEndTime() {
        return endTime;
    }

    public AdminBookingDTO setEndTime(String endTime) {
        this.endTime = endTime;
        return this;
    }

    public int getDuration() {
        return duration;
    }

    public AdminBookingDTO setDuration(int duration) {
        this.duration = duration;
        return this;
    }

    public double getAmount() {
        return amount;
    }

    public AdminBookingDTO setAmount(double amount) {
        this.amount = amount;
        return this;
    }

    public String getUsername() {
        return username;
    }

    public AdminBookingDTO setUsername(String username) {
        this.username = username;
        return this;
    }
}
