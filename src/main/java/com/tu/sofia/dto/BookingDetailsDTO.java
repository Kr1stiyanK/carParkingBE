package com.tu.sofia.dto;

import com.tu.sofia.model.BookingDetails;

import java.time.LocalDateTime;

public class BookingDetailsDTO {

    private Long id;
    private String text;
    private LocalDateTime start;
    private LocalDateTime end;
    private Long resourceId;
    private Long userId;

    public BookingDetailsDTO(BookingDetails bookingDetails) {
        this.id = bookingDetails.getId();
        this.text = bookingDetails.getText();
        this.start = bookingDetails.getStart();
        this.end = bookingDetails.getEnd();
        this.resourceId = bookingDetails.getParkingSpaceId();
        this.userId = bookingDetails.getUserId();
    }

    public Long getId() {
        return id;
    }

    public BookingDetailsDTO setId(Long id) {
        this.id = id;
        return this;
    }

    public String getText() {
        return text;
    }

    public BookingDetailsDTO setText(String text) {
        this.text = text;
        return this;
    }

    public LocalDateTime getStart() {
        return start;
    }

    public BookingDetailsDTO setStart(LocalDateTime start) {
        this.start = start;
        return this;
    }

    public LocalDateTime getEnd() {
        return end;
    }

    public BookingDetailsDTO setEnd(LocalDateTime end) {
        this.end = end;
        return this;
    }

    public Long getResourceId() {
        return resourceId;
    }

    public BookingDetailsDTO setResourceId(Long resourceId) {
        this.resourceId = resourceId;
        return this;
    }

    public Long getUserId() {
        return userId;
    }

    public BookingDetailsDTO setUserId(Long userId) {
        this.userId = userId;
        return this;
    }
}
