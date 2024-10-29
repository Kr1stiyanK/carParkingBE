package com.tu.sofia.dto;

import java.time.LocalDateTime;

public class QuickBookingDTO {

    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private String paymentMethod;
    private Double amount;


    public LocalDateTime getStartTime() {
        return startTime;
    }

    public QuickBookingDTO setStartTime(LocalDateTime startTime) {
        this.startTime = startTime;
        return this;
    }

    public LocalDateTime getEndTime() {
        return endTime;
    }

    public QuickBookingDTO setEndTime(LocalDateTime endTime) {
        this.endTime = endTime;
        return this;
    }

    public String getPaymentMethod() {
        return paymentMethod;
    }

    public QuickBookingDTO setPaymentMethod(String paymentMethod) {
        this.paymentMethod = paymentMethod;
        return this;
    }

    public Double getAmount() {
        return amount;
    }

    public QuickBookingDTO setAmount(Double amount) {
        this.amount = amount;
        return this;
    }
}
