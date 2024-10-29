package com.tu.sofia.dto;

import java.time.LocalDateTime;

public class BookingCreateDTO {

    private String start;
    private String end;
    private String text;
    private Long resource;
    private double amount;

    public BookingCreateDTO setResource(Long resource) {
        this.resource = resource;
        return this;
    }

    public Long getResource() {
        return resource;
    }

    public String getStart() {
        return start;
    }

    public BookingCreateDTO setStart(String start) {
        this.start = start;
        return this;
    }

    public String getEnd() {
        return end;
    }

    public BookingCreateDTO setEnd(String end) {
        this.end = end;
        return this;
    }

    public String getText() {
        return text;
    }

    public BookingCreateDTO setText(String text) {
        this.text = text;
        return this;
    }

    public double getAmount() {
        return amount;
    }

    public BookingCreateDTO setAmount(double amount) {
        this.amount = amount;
        return this;
    }
}
