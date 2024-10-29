package com.tu.sofia.model;

import jakarta.persistence.*;

@Entity
@Table(name = "parking_spaces")
public class ParkingSpaceEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;


    public Long getId() {
        return id;
    }

    public ParkingSpaceEntity setId(Long id) {
        this.id = id;
        return this;
    }

    public String getName() {
        return name;
    }

    public ParkingSpaceEntity setName(String number) {
        this.name = number;
        return this;
    }
}
