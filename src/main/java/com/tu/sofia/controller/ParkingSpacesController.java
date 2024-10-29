package com.tu.sofia.controller;

import com.tu.sofia.dto.*;
import com.tu.sofia.model.BookingDetails;
import com.tu.sofia.model.ParkingSpaceEntity;
import com.tu.sofia.service.ParkingSpaceBookingService;
import com.tu.sofia.service.ParkingSpaceService;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@CrossOrigin(origins = "http://localhost:4200")
@RequestMapping("/api")
public class ParkingSpacesController {

    private static final Logger logger = LoggerFactory.getLogger(ParkingSpacesController.class);

    private final ParkingSpaceService parkingSpaceService;

    private final ParkingSpaceBookingService bookingService;

    public ParkingSpacesController(ParkingSpaceService parkingSpaceService, ParkingSpaceBookingService bookingService) {
        this.parkingSpaceService = parkingSpaceService;
        this.bookingService = bookingService;
    }

    @GetMapping("/bookings")
    public List<BookingDetails> getBookings(@RequestParam("from") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from, @RequestParam("to") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to) {
        return bookingService.getBookingsBetween(from, to);
    }

    @GetMapping("/parkingspaces")
    public Iterable<ParkingSpaceEntity> getAllParkingSpaces() {
        return parkingSpaceService.getAllParkingSpaces();
    }

    @PostMapping("/parkingspaces/create")
    @Transactional
    public ResponseEntity<BookingDetails> createBooking(@RequestBody BookingCreateDTO params, Authentication authentication) {
        try {
            BookingDetails bookingDetails = this.bookingService.createBooking(params, authentication);
            return ResponseEntity.ok(bookingDetails);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @PostMapping("/parkingspaces/edit")
    public ResponseEntity<?> editBooking(@RequestBody BookingEditDTO params) {
        boolean available = bookingService.isBookingAvailableWhenEdit(params.getResourceId(), params.getStart(), params.getEnd(), params.getId());
        if (!available) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("The selected time range overlaps with another booking.");
        }

        try {
            BookingDetails editedBooking = bookingService.editBooking(params);
            Map<String, String> response = new HashMap<>();
            response.put("message", "Booking updated successfully.");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Failed to update booking.");
        }
    }


    @PostMapping("/parkingspaces/delete")
    public ResponseEntity<Void> deleteBooking(@RequestBody BookingDeleteDTO params) {
        bookingService.deleteBooking(params.getId());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/parkingspaces/move")
    public ResponseEntity<BookingDetails> moveBooking(@RequestBody BookingMoveDTO params) {
        logger.info("Received request to move booking with params: {}", params);
        try {
            BookingDetails moveBooking = bookingService.moveBooking(params);
            logger.info("Booking moved successfully: {}", moveBooking);
            return ResponseEntity.ok(moveBooking);
        } catch (IllegalArgumentException e) {
            logger.error("Error moving booking: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
    }

    @PostMapping("/parkingspaces/check-availability")
    public ResponseEntity<?> checkAvailability(@RequestBody BookingEditAvailabilityDTO request) {
        boolean available = bookingService.isParkingSpaceAvailable(request.getResourceId(), request.getStartTime(), request.getEndTime(), request.getBookingId());
        return ResponseEntity.ok().body(Map.of("available", available));
    }

}
