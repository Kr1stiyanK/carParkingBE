package com.tu.sofia.dto;

import java.time.LocalDateTime;

public class BookingEditAvailabilityDTO {
    private Long resourceId;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private Long bookingId;

    public Long getResourceId() {
        return resourceId;
    }

    public BookingEditAvailabilityDTO setResourceId(Long resourceId) {
        this.resourceId = resourceId;
        return this;
    }

    public LocalDateTime getStartTime() {
        return startTime;
    }

    public BookingEditAvailabilityDTO setStartTime(LocalDateTime startTime) {
        this.startTime = startTime;
        return this;
    }

    public LocalDateTime getEndTime() {
        return endTime;
    }

    public BookingEditAvailabilityDTO setEndTime(LocalDateTime endTime) {
        this.endTime = endTime;
        return this;
    }

    public Long getBookingId() {
        return bookingId;
    }

    public BookingEditAvailabilityDTO setBookingId(Long bookingId) {
        this.bookingId = bookingId;
        return this;
    }
}
