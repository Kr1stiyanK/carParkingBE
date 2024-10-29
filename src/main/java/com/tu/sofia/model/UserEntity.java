package com.tu.sofia.model;

import jakarta.persistence.*;


@Entity
@Table(name = "users")
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false,
            unique = true)
    private String email;

    @Column(nullable = false)
    private String name;

    private String password;

    @OneToOne
    @JoinColumn(name = "role_id")
    private UserRoleEntity role;

    public Long getId() {
        return id;
    }

    public UserEntity setId(Long id) {
        this.id = id;
        return this;
    }

    public String getEmail() {
        return email;
    }

    public UserEntity setEmail(String email) {
        this.email = email;
        return this;
    }

    public String getPassword() {
        return password;
    }

    public UserEntity setPassword(String password) {
        this.password = password;
        return this;
    }

    public String getName() {
        return name;
    }

    public UserEntity setName(String firstName) {
        this.name = firstName;
        return this;
    }


    public UserRoleEntity getRole() {
        return role;
    }

    public UserEntity setRole(UserRoleEntity userRoles) {
        this.role = userRoles;
        return this;
    }
}
