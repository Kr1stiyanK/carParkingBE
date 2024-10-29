package com.tu.sofia.dto;

import java.time.LocalDateTime;

public class BookingAvailabilityDTO {

    private LocalDateTime date;
    private LocalDateTime startTime;
    private LocalDateTime endTime;

    public LocalDateTime getDate() {
        return date;
    }

    public BookingAvailabilityDTO setDate(LocalDateTime date) {
        this.date = date;
        return this;
    }

    public LocalDateTime getStartTime() {
        return startTime;
    }

    public BookingAvailabilityDTO setStartTime(LocalDateTime startTime) {
        this.startTime = startTime;
        return this;
    }

    public LocalDateTime getEndTime() {
        return endTime;
    }

    public BookingAvailabilityDTO setEndTime(LocalDateTime endTime) {
        this.endTime = endTime;
        return this;
    }
}
