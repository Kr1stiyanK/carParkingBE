package com.tu.sofia.controller;

import com.tu.sofia.dto.UserLoginDTO;
import com.tu.sofia.dto.LoginResponseDTO;
import com.tu.sofia.model.UserEntity;
import com.tu.sofia.service.UserEntityService;
import com.tu.sofia.utils.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin(origins = "http://localhost:4200")
@RequestMapping("/login")
public class LoginController {

    private final AuthenticationManager authenticationManager;

    private final UserEntityService userEntityService;

    private final JwtUtil jwtUtil;

    public LoginController(AuthenticationManager authenticationManager, UserEntityService userEntityService, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.userEntityService = userEntityService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping
    public ResponseEntity<LoginResponseDTO> login(@RequestBody UserLoginDTO userLoginDTO) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userLoginDTO.getEmail(), userLoginDTO.getPassword())
            );
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        UserDetails userDetails;
        try {
            userDetails = userEntityService.loadUserByUsername(userLoginDTO.getEmail());
        } catch (UsernameNotFoundException exception) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        UserEntity user = userEntityService.loadByUsername(userLoginDTO.getEmail());
        String jwtToken = jwtUtil.generateToken(userLoginDTO.getEmail(), user.getId());

        return ResponseEntity.ok(new LoginResponseDTO(jwtToken));
    }
}
