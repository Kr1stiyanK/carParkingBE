package com.tu.sofia.repositories;

import com.tu.sofia.enums.UserRoleEnum;
import com.tu.sofia.model.UserRoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRoleEntity, Long> {

    UserRoleEntity findByRole(UserRoleEnum userRoleEnum);
}
