package com.tu.sofia.dto;

public class BookingFetchDTO {
    private String date;
    private String startTime;
    private String endTime;
    private int duration;
    private double amount;


    public String getDate() {
        return date;
    }

    public BookingFetchDTO setDate(String date) {
        this.date = date;
        return this;
    }

    public String getStartTime() {
        return startTime;
    }

    public BookingFetchDTO setStartTime(String startTime) {
        this.startTime = startTime;
        return this;
    }

    public String getEndTime() {
        return endTime;
    }

    public BookingFetchDTO setEndTime(String endTime) {
        this.endTime = endTime;
        return this;
    }

    public int getDuration() {
        return duration;
    }

    public BookingFetchDTO setDuration(int duration) {
        this.duration = duration;
        return this;
    }

    public double getAmount() {
        return amount;
    }

    public BookingFetchDTO setAmount(double amount) {
        this.amount = amount;
        return this;
    }
}
