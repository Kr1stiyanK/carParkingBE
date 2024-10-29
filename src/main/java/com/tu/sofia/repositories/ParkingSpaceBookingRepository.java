package com.tu.sofia.repositories;

import com.tu.sofia.model.BookingDetails;
import com.tu.sofia.model.ParkingSpaceEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface ParkingSpaceBookingRepository extends JpaRepository<BookingDetails, Long> {

    List<BookingDetails> findByStartBetween(LocalDateTime from, LocalDateTime to);

    boolean existsByResourceAndStartLessThanAndEndGreaterThanAndIdNot(ParkingSpaceEntity resource, LocalDateTime end, LocalDateTime start, Long id);


    boolean existsByResourceIdAndStartLessThanAndEndGreaterThanAndIdNot(Long resourceId, LocalDateTime endTime, LocalDateTime startTime, Long bookingId);

    List<BookingDetails> findByResourceId(Long resourceId);

    @Query("SELECT b FROM BookingDetails b WHERE b.resource.id = :resourceId AND b.id != :bookingId AND ((b.start < :endTime AND b.end > :startTime) OR (b.start = :endTime OR b.end = :startTime))")
    List<BookingDetails> findConflictingBookings(@Param("resourceId") Long resourceId, @Param("startTime") LocalDateTime startTime, @Param("endTime") LocalDateTime endTime, @Param("bookingId") Long bookingId);

}
