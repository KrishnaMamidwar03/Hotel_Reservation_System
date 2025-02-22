package com.book.service;

import com.book.DTO.AdminBookingDto;
import com.book.entities.Bookings;
import com.book.entities.Hotels;
import com.book.entities.Room;
import com.book.repository.AdminBookingRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class AdminBookingService {

    @Autowired
    private AdminBookingRepository bookingRepository;

    public List<AdminBookingDto> getAllBookings() {
        List<Bookings> bookings = bookingRepository.findAll();
        return bookings.stream().map(this::convertToDto).collect(Collectors.toList());
    }

    public AdminBookingDto getBookingById(Long id) {
        Optional<Bookings> booking = bookingRepository.findById(id);
        return booking.map(this::convertToDto).orElse(null);
    }

    private AdminBookingDto convertToDto(Bookings booking) {
        Hotels hotel = booking.getHotel();
        Room room = booking.getRoom();
        return new AdminBookingDto(
            booking.getBookingid(),
            booking.getUser().getFirstname(),
            booking.getUser().getLastname(),
            hotel != null ? hotel.getHotelname() : null,
            hotel != null && hotel.getCity() != null ? hotel.getCity().getName() : null,
            room != null ? room.getRoomtype().name() : null,
            booking.getCheckindate(),
            booking.getCheckoutdate()
        );
    }
}
