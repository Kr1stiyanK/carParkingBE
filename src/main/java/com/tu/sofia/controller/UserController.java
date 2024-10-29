package com.tu.sofia.controller;

import com.tu.sofia.dto.*;
import com.tu.sofia.model.OrderEntity;
import com.tu.sofia.model.UserEntity;
import com.tu.sofia.service.ParkingSpaceBookingService;
import com.tu.sofia.service.UserEntityService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@CrossOrigin(origins = "http://localhost:4200")
@RequestMapping("/api")
public class UserController {

    private final UserEntityService userEntityService;

    private final PasswordEncoder passwordEncoder;

    private final ParkingSpaceBookingService parkingSpaceBookingService;


    public UserController(UserEntityService userEntityService, PasswordEncoder passwordEncoder, ParkingSpaceBookingService parkingSpaceBookingService) {
        this.userEntityService = userEntityService;
        this.parkingSpaceBookingService = parkingSpaceBookingService;
        this.passwordEncoder = new BCryptPasswordEncoder();
    }


    @GetMapping("/role")
    public Map<String, String> getUserRole() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String role = authentication.getAuthorities().stream()
                    .map(grantedAuthority -> grantedAuthority.getAuthority())
                    .findFirst()
                    .orElse("ROLE_USER");
            return Collections.singletonMap("role", role);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
        return null;
    }


    @PutMapping("/update-email")
    public ResponseEntity<?> updateEmail(@RequestBody UpdateProfileDTO updateEmailRequest) {
        try {
            UserEntity user = userEntityService.loadByUsername(updateEmailRequest.getCurrentEmail());
            if (user == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("User not found");
            }
            user.setEmail(updateEmailRequest.getNewEmail());
            userEntityService.updateUsername(user);
            Map<String, String> response = new HashMap<>();
            response.put("message", "Email updated successfully");
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(response);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).contentType(MediaType.APPLICATION_JSON).body(errorResponse);
        }
    }


    @PutMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordDTO request) {
        UserEntity user = userEntityService.loadByUsername(request.getEmail());
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userEntityService.updatePassword(user);

        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }


    @GetMapping("/my-bookings")
    public ResponseEntity<List<BookingFetchDTO>> getMyBookings(@RequestParam String email) {
        List<BookingFetchDTO> bookings = parkingSpaceBookingService.getBookingsByEmail(email);
        return ResponseEntity.ok(bookings);
    }

}
