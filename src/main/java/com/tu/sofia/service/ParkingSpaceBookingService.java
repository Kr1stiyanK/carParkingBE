package com.tu.sofia.service;

import com.tu.sofia.dto.*;
import com.tu.sofia.model.BookingDetails;
import com.tu.sofia.model.OrderEntity;
import com.tu.sofia.model.ParkingSpaceEntity;
import com.tu.sofia.model.UserEntity;
import com.tu.sofia.repositories.OrderEntityRepository;
import com.tu.sofia.repositories.ParkingSpaceBookingRepository;
import com.tu.sofia.repositories.ParkingSpaceRepository;
import com.tu.sofia.repositories.UserEntityRepository;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class ParkingSpaceBookingService {

    private static final Logger logger = LoggerFactory.getLogger(ParkingSpaceBookingService.class);

    private final ParkingSpaceRepository parkingSpaceRepository;

    private final ParkingSpaceBookingRepository spaceBookingRepository;

    private final UserEntityRepository userEntityRepository;

    private final OrderEntityRepository orderEntityRepository;

    public ParkingSpaceBookingService(ParkingSpaceRepository parkingSpaceRepository, ParkingSpaceBookingRepository spaceBookingRepository, UserEntityRepository userEntityRepository, OrderEntityRepository orderEntityRepository) {
        this.parkingSpaceRepository = parkingSpaceRepository;
        this.spaceBookingRepository = spaceBookingRepository;
        this.userEntityRepository = userEntityRepository;
        this.orderEntityRepository = orderEntityRepository;
    }


    public List<BookingDetails> getBookingsBetween(LocalDateTime from, LocalDateTime to) {
        List<BookingDetails> bookings = spaceBookingRepository.findByStartBetween(from, to);
        return bookings.stream()
                .map(this::adjustEndTime)
                .collect(Collectors.toList());
    }

    private BookingDetails adjustEndTime(BookingDetails booking) {
        BookingDetails adjustedBooking = new BookingDetails()
                .setId(booking.getId())
                .setText(booking.getText())
                .setStart(booking.getStart())
                .setEnd(booking.getEnd().plusHours(1))
                .setResource(booking.getResource())
                .setUserId(booking.getUserId());
        return adjustedBooking;
    }


    public BookingDetails createBooking(BookingCreateDTO bookingCreateDTO, Authentication authentication) {
        ParkingSpaceEntity parkingSpaceEntity = this.parkingSpaceRepository.findById(bookingCreateDTO.getResource()).orElseThrow(IllegalArgumentException::new);

        UserEntity currentUser = this.userEntityRepository.findByEmail(authentication.getName()).orElseThrow(() -> new UsernameNotFoundException("User with email " + authentication.getName() + " does not exists"));

        DateTimeFormatter formatter = DateTimeFormatter.ISO_DATE_TIME;
        LocalDateTime start = LocalDateTime.parse(bookingCreateDTO.getStart(), formatter);
        LocalDateTime end = LocalDateTime.parse(bookingCreateDTO.getEnd(), formatter).minusHours(1);


        BookingDetails booking = new BookingDetails()
                .setUserId(currentUser.getId())
                .setStart(start)
                .setEnd(end)
                .setResource(parkingSpaceEntity);

        BookingDetails booking2 = new BookingDetails()
                .setUserId(currentUser.getId())
                .setStart(start)
                .setEnd(end.plusHours(1))
                .setResource(parkingSpaceEntity);

        OrderEntity order = new OrderEntity()
                .setUser(currentUser)
                .setBookingDetails(booking)
                .setAmount(bookingCreateDTO.getAmount());

        this.orderEntityRepository.save(order);

        BookingDetails savedBooking = this.spaceBookingRepository.save(booking);
        savedBooking.setText("Booking № " + savedBooking.getId());
        spaceBookingRepository.save(savedBooking);

        booking2.setId(savedBooking.getId())
                .setText("Booking № " + savedBooking.getId());
        return booking2;

    }

    @Transactional
    public void deleteBooking(Long id) {
        spaceBookingRepository.deleteById(id);
    }

    public BookingDetails moveBooking(BookingMoveDTO params) {
        logger.info("Moving booking with params: {}", params);

        if (!isMoveBookingAvailable(params.getResourceId(), params.getStartTime(), params.getEndTime(), params.getBookingId())) {
            logger.warn("The new time overlaps with an existing booking.");
            throw new IllegalArgumentException("The new time overlaps with an existing booking.");
        }

        BookingDetails booking = spaceBookingRepository.findById(params.getBookingId()).orElseThrow(() -> {
            logger.error("Booking with id {} not found", params.getBookingId());
            return new IllegalArgumentException("Booking not found");
        });

        ParkingSpaceEntity parkingSpaceEntity = parkingSpaceRepository.findById(params.getResourceId()).orElseThrow(() -> {
            logger.error("Parking space with id {} not found", params.getResourceId());
            return new IllegalArgumentException("Parking space not found");
        });
        booking.setStart(params.getStartTime())
                .setEnd(params.getEndTime().minusHours(1))
                .setResource(parkingSpaceEntity);

        this.spaceBookingRepository.save(booking);
        logger.info("Booking moved successfully: {}", booking);

        return new BookingDetails()
                .setStart(params.getStartTime())
                .setEnd(params.getEndTime().plusHours(1))
                .setResource(parkingSpaceEntity);
    }

    public List<BookingFetchDTO> getBookingsByEmail(String email) {
        List<OrderEntity> orders = orderEntityRepository.findByUserEmail(email);
        return orders.stream().map(this::convertToDTO).collect(Collectors.toList());
    }

    private BookingFetchDTO convertToDTO(OrderEntity order) {
        BookingDetails details = order.getBookingDetails();
        int duration = (int) Duration.between(details.getStart(), details.getEnd()).toHours();
        return new BookingFetchDTO()
                .setStartTime(details.getStart().toString())
                .setEndTime(details.getEnd().toString())
                .setDate(details.getStart().toLocalDate().toString())
                .setDuration(duration)
                .setAmount(order.getAmount());
    }

    public boolean isParkingSpaceAvailable(LocalDateTime startTime, LocalDateTime endTime) {
        List<ParkingSpaceEntity> availableParkingSpaceEntities = this.parkingSpaceRepository.findAvailableParkingSpaces(startTime, endTime);
        return !availableParkingSpaceEntities.isEmpty();
    }

    public boolean isBookingAvailableWhenEdit(Long resourceId, LocalDateTime startTime, LocalDateTime endTime, Long bookingId) {
        List<BookingDetails> bookings = spaceBookingRepository.findByResourceId(resourceId);
        for (BookingDetails booking : bookings) {
            if (!booking.getId().equals(bookingId) && booking.getStart().isBefore(endTime) && booking.getEnd().isAfter(startTime)) {
                return false;
            }
        }
        return true;
    }

    public boolean isParkingSpaceAvailable(Long resourceId, LocalDateTime startTime, LocalDateTime endTime, Long bookingId) {
        List<BookingDetails> conflictingBookings = spaceBookingRepository.findConflictingBookings(resourceId, startTime, endTime, bookingId);
        return conflictingBookings.isEmpty();
    }

    public OrderEntity createQuickBooking(QuickBookingDTO request) {
        List<ParkingSpaceEntity> availableSpaces = parkingSpaceRepository.findAvailableParkingSpaces(request.getStartTime(), request.getEndTime());
        if (availableSpaces.isEmpty()) {
            throw new RuntimeException("No available parking space for the selected time.");
        }

        ParkingSpaceEntity availableSpace = availableSpaces.get(0);
        Optional<UserEntity> guestUser = userEntityRepository.findByName("guest");

        if (guestUser.isEmpty()) {
            throw new RuntimeException("Guest user not found.");
        }

        BookingDetails bookingDetails = new BookingDetails()
                .setStart(request.getStartTime())
                .setEnd(request.getEndTime())
                .setResource(availableSpace)
                .setText("Guest booking")
                .setUserId(guestUser.get().getId());

        this.spaceBookingRepository.save(bookingDetails);

        OrderEntity order = new OrderEntity()
                .setBookingDetails(bookingDetails)
                .setAmount(calculateAmount(request.getStartTime(), request.getEndTime()))
                .setUser(guestUser.get());
        orderEntityRepository.save(order);

        return order;
    }

    public boolean isMoveBookingAvailable(Long resourceId, LocalDateTime startTime, LocalDateTime endTime, Long bookingId) {
        boolean exists = spaceBookingRepository.existsByResourceIdAndStartLessThanAndEndGreaterThanAndIdNot(resourceId, endTime, startTime, bookingId);
        logger.info("Checking availability for resourceId: {}, startTime: {}, endTime: {}, bookingId: {}", resourceId, startTime, endTime, bookingId);
        logger.info("Exists overlapping booking: {}", exists);
        return !exists;
    }

    public BookingDetails editBooking(BookingEditDTO bookingEditDTO) {
        BookingDetails booking = this.spaceBookingRepository.findById(bookingEditDTO.getId())
                .orElseThrow(() -> new IllegalArgumentException("Booking not found"));

        ParkingSpaceEntity parkingSpaceEntity = this.parkingSpaceRepository.findById(bookingEditDTO.getResourceId())
                .orElseThrow(() -> new IllegalArgumentException("Parking space not found"));

        OrderEntity orderForBooking = this.orderEntityRepository.findById(booking.getOrder().getId())
                .orElseThrow(() -> new IllegalArgumentException("Order not found"));

        LocalDateTime newStart = bookingEditDTO.getStart();
        LocalDateTime newEnd = bookingEditDTO.getEnd();

        boolean overlaps = this.spaceBookingRepository.existsByResourceAndStartLessThanAndEndGreaterThanAndIdNot(parkingSpaceEntity, newEnd, newStart, booking.getId());
        if (overlaps) {
            throw new IllegalArgumentException("The selected time range overlaps with another booking.");
        }

        orderForBooking.setAmount(bookingEditDTO.getAmount());
        this.orderEntityRepository.save(orderForBooking);

        booking.setStart(newStart);
        booking.setEnd(newEnd);
        booking.setResource(parkingSpaceEntity);

        return this.spaceBookingRepository.save(booking);
    }

    private double calculateAmount(LocalDateTime startTime, LocalDateTime endTime) {
        long hours = Duration.between(startTime, endTime).toHours();
        return hours * 3;
    }

    public List<AdminBookingDTO> getAllBookings() {
        return this.orderEntityRepository.findAll()
                .stream().map(this::convertToAdminDTO).collect(Collectors.toList());
    }

    private AdminBookingDTO convertToAdminDTO(OrderEntity order) {
        BookingDetails details = order.getBookingDetails();
        int duration = (int) Duration.between(details.getStart(), details.getEnd()).toHours();
        String username = (order.getUser() != null && order.getUser().getEmail() != null && !order.getUser().getEmail().isEmpty())
                ? order.getUser().getEmail()
                : "Guest User";
        return new AdminBookingDTO()
                .setStartTime(details.getStart().toString())
                .setEndTime(details.getEnd().toString())
                .setDate(details.getStart().toLocalDate().toString())
                .setDuration(duration)
                .setAmount(order.getAmount())
                .setUsername(username);
    }
}
