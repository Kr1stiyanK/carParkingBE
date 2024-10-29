package com.tu.sofia.controller;

import com.tu.sofia.dto.BookingAvailabilityDTO;
import com.tu.sofia.dto.QuickBookingDTO;
import com.tu.sofia.model.OrderEntity;
import com.tu.sofia.service.ParkingSpaceBookingService;
import com.tu.sofia.service.UserEntityService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@CrossOrigin(origins = "http://localhost:4200")
@RequestMapping("/api/guest")
public class GuestBookingController {

    private final UserEntityService userEntityService;

    private final PasswordEncoder passwordEncoder;

    private final ParkingSpaceBookingService parkingSpaceBookingService;

    public GuestBookingController(UserEntityService userEntityService, PasswordEncoder passwordEncoder, ParkingSpaceBookingService parkingSpaceBookingService) {
        this.userEntityService = userEntityService;
        this.passwordEncoder = passwordEncoder;
        this.parkingSpaceBookingService = parkingSpaceBookingService;
    }


    @PostMapping("/check-availability")
    public ResponseEntity<?> checkAvailability(@RequestBody BookingAvailabilityDTO request) {
        boolean available = parkingSpaceBookingService.isParkingSpaceAvailable(request.getStartTime(), request.getEndTime());
        return ResponseEntity.ok().body(Map.of("available", available));
    }

    @PostMapping("/quick-booking")
    public ResponseEntity<?> quickBooking(@RequestBody QuickBookingDTO request) {
        try {
            OrderEntity booking = parkingSpaceBookingService.createQuickBooking(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(booking);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }
}
