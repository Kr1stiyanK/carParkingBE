package com.tu.sofia;

import com.tu.sofia.enums.UserRoleEnum;
import com.tu.sofia.model.UserEntity;
import com.tu.sofia.model.UserRoleEntity;
import com.tu.sofia.repositories.UserEntityRepository;
import com.tu.sofia.repositories.UserRoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

@Configuration
public class AppInitializer implements CommandLineRunner {

    private final UserRoleRepository roleRepo;

    private final PasswordEncoder passwordEncoder;

    private final UserEntityRepository userRepo;

    public AppInitializer(UserRoleRepository roleRepo, PasswordEncoder passwordEncoder, UserEntityRepository userRepo) {
        this.roleRepo = roleRepo;
        this.passwordEncoder = passwordEncoder;
        this.userRepo = userRepo;
    }


    @Override
    public void run(String... args) throws Exception {
//        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
//        keyGen.init(256); // for example, HMAC-SHA256
//        SecretKey secretKey = keyGen.generateKey();
//        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
//        System.out.println("Secret Key: " + encodedKey);


//        UserRoleEntity adminRole = roleRepo.findByRole(UserRoleEnum.ADMIN);
//        UserEntity admin = new UserEntity()
//                .setId(1L)
//                .setEmail("admin@mail.com")
//                .setName("admin")
//                .setPassword(passwordEncoder.encode("admin"))
//                .setRole(adminRole);
//        this.userRepo.save(admin);
//
//
//        UserRoleEntity guestRole = roleRepo.findByRole(UserRoleEnum.GUEST);
//        UserEntity guest = new UserEntity()
//                .setId(2L)
//                .setEmail("")
//                .setName("guest")
//                .setPassword(null)
//                .setRole(guestRole);
//        this.userRepo.save(guest);
    }
}
