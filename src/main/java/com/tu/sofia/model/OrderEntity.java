package com.tu.sofia.model;

import jakarta.persistence.*;

@Entity
@Table(name = "orders")
public class OrderEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private UserEntity user;

    @OneToOne
    @JoinColumn(name = "booking_id")
    private BookingDetails bookingDetails;

    private double amount;

    public Long getId() {
        return id;
    }

    public OrderEntity setId(Long id) {
        this.id = id;
        return this;
    }

    public UserEntity getUser() {
        return user;
    }

    public OrderEntity setUser(UserEntity user) {
        this.user = user;
        return this;
    }

    public BookingDetails getBookingDetails() {
        return bookingDetails;
    }

    public OrderEntity setBookingDetails(BookingDetails bookingDetails) {
        this.bookingDetails = bookingDetails;
        return this;
    }

    public double getAmount() {
        return amount;
    }

    public OrderEntity setAmount(double amount) {
        this.amount = amount;
        return this;
    }
}
