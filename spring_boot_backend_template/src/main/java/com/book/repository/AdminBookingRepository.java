package com.book.repository;

import com.book.entities.Bookings;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AdminBookingRepository extends JpaRepository<Bookings, Long> {
    // Custom query method if needed
}
