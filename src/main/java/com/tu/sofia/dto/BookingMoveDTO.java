package com.tu.sofia.dto;

import java.time.LocalDateTime;

public class BookingMoveDTO {
    private Long bookingId;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private Long resourceId;

    public Long getBookingId() {
        return bookingId;
    }

    public BookingMoveDTO setBookingId(Long bookingId) {
        this.bookingId = bookingId;
        return this;
    }

    public LocalDateTime getStartTime() {
        return startTime;
    }

    public BookingMoveDTO setStartTime(LocalDateTime startTime) {
        this.startTime = startTime;
        return this;
    }

    public LocalDateTime getEndTime() {
        return endTime;
    }

    public BookingMoveDTO setEndTime(LocalDateTime endTime) {
        this.endTime = endTime;
        return this;
    }

    public Long getResourceId() {
        return resourceId;
    }

    public BookingMoveDTO setResourceId(Long resourceId) {
        this.resourceId = resourceId;
        return this;
    }
}
