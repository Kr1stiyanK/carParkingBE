package com.tu.sofia.service;

import com.tu.sofia.dto.UserRegistrationDTO;
import com.tu.sofia.enums.UserRoleEnum;
import com.tu.sofia.model.UserEntity;
import com.tu.sofia.model.UserRoleEntity;
import com.tu.sofia.repositories.UserEntityRepository;
import com.tu.sofia.repositories.UserRoleRepository;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collector;

@Service
@Lazy
public class UserEntityService implements UserDetailsService {

    private final UserEntityRepository userRepo;

    private final UserRoleRepository roleRepo;

    private final PasswordEncoder passwordEncoder;

    public UserEntityService(UserEntityRepository userRepo, UserRoleRepository roleRepo, PasswordEncoder passwordEncoder) {
        this.userRepo = userRepo;
        this.roleRepo = roleRepo;
        this.passwordEncoder = passwordEncoder;
    }


    public UserEntity createCustomer(UserRegistrationDTO signupRequest) {
        if (userRepo.existsByEmail(signupRequest.getEmail())) {
            return null;
        }

        UserRoleEntity role = roleRepo.findByRole(UserRoleEnum.USER);
        if (role == null) {
            role = new UserRoleEntity().setRole(UserRoleEnum.USER);
            role = roleRepo.save(role);
        }

        UserEntity customer = new UserEntity()
                .setEmail(signupRequest.getEmail())
                .setName(signupRequest.getName())
                .setPassword(passwordEncoder.encode(signupRequest.getPassword()))
                .setRole(role);

        UserEntity createdCustomer = userRepo.save(customer);
        return createdCustomer;
    }


    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        UserEntity user = this.userRepo.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("Customer not found with email: " + email));

        return new User(user.getEmail(), user.getPassword(), Collections.singletonList(new SimpleGrantedAuthority(user.getRole().getRole().name())));
    }

    public UserEntity loadByUsername(String email) {
        return this.userRepo.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("Customer not found with email: " + email));
    }

    public void updateUsername(UserEntity userEntity) {
        this.userRepo.save(userEntity);
    }

    public void updatePassword(UserEntity userEntity) {
        this.userRepo.save(userEntity);
    }

    public List<UserEntity> findAllUsers() {
        return this.userRepo.findAll();
    }
}
