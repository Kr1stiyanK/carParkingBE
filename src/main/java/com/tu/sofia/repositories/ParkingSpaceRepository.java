package com.tu.sofia.repositories;

import com.tu.sofia.model.ParkingSpaceEntity;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface ParkingSpaceRepository extends JpaRepository<ParkingSpaceEntity, Long> {

    List<ParkingSpaceEntity> findAll();

    @Query("SELECT ps FROM ParkingSpaceEntity ps WHERE NOT EXISTS " +
            "(SELECT 1 FROM BookingDetails bd WHERE bd.resource = ps AND " +
            "((:startTime BETWEEN bd.start AND bd.end) OR (:endTime BETWEEN bd.start AND bd.end)))")
    List<ParkingSpaceEntity> findFirstAvailableParkingSpace(@Param("startTime") LocalDateTime startTime, @Param("endTime") LocalDateTime endTime, Pageable pageable);

    default ParkingSpaceEntity findFirstAvailableParkingSpace(LocalDateTime startTime, LocalDateTime endTime) {
        List<ParkingSpaceEntity> result = findFirstAvailableParkingSpace(startTime, endTime, PageRequest.of(0, 1));
        return result.isEmpty() ? null : result.get(0);
    }


    @Query("SELECT ps FROM ParkingSpaceEntity ps WHERE ps.id NOT IN (SELECT b.resource.id FROM BookingDetails b WHERE (b.start < :endTime AND b.end >= :startTime))")
    List<ParkingSpaceEntity> findAvailableParkingSpaces(@Param("startTime") LocalDateTime startTime, @Param("endTime") LocalDateTime endTime);


}
