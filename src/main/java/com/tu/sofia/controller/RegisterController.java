package com.tu.sofia.controller;

import com.tu.sofia.dto.UserRegistrationDTO;
import com.tu.sofia.model.UserEntity;
import com.tu.sofia.service.UserEntityService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin(origins = "http://localhost:4200")
@RequestMapping("/register")
public class RegisterController {

    private final UserEntityService userEntityService;

    public RegisterController(UserEntityService userEntityService) {
        this.userEntityService = userEntityService;
    }

    @PostMapping
    public ResponseEntity<?> registerUser(@RequestBody UserRegistrationDTO signupRequest) {
        UserEntity createdCustomer = userEntityService.createCustomer(signupRequest);
        if (createdCustomer != null) {
            return ResponseEntity.status(HttpStatus.CREATED).body(createdCustomer);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Failed to create customer");
        }
    }
}
