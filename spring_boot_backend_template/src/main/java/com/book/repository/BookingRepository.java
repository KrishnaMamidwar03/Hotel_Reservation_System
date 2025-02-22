package com.book.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.book.entities.Bookings;
import com.book.entities.User;

public interface BookingRepository extends JpaRepository<Bookings, Long> {
	 List<Bookings> findByUser(User user);

}
