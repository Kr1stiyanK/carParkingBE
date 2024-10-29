package com.tu.sofia.dto;

import java.time.LocalDateTime;

public class BookingEditDTO {
    private Long id;
    private LocalDateTime start;
    private LocalDateTime end;
    private Long resourceId;
    private double amount;

    public Long getId() {
        return id;
    }

    public BookingEditDTO setId(Long id) {
        this.id = id;
        return this;
    }

    public LocalDateTime getStart() {
        return start;
    }

    public BookingEditDTO setStart(LocalDateTime start) {
        this.start = start;
        return this;
    }

    public LocalDateTime getEnd() {
        return end;
    }

    public BookingEditDTO setEnd(LocalDateTime end) {
        this.end = end;
        return this;
    }

    public Long getResourceId() {
        return resourceId;
    }

    public BookingEditDTO setResourceId(Long resourceId) {
        this.resourceId = resourceId;
        return this;
    }

    public double getAmount() {
        return amount;
    }

    public BookingEditDTO setAmount(double amount) {
        this.amount = amount;
        return this;
    }
}
