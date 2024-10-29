package com.tu.sofia.repositories;

import com.tu.sofia.model.OrderEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface OrderEntityRepository extends JpaRepository<OrderEntity, Long> {

    List<OrderEntity> findByUserEmail(String email);

    void deleteByBookingDetailsId(Long bookingDetailsId);
}
