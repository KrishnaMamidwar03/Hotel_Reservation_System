package com.book.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.book.entities.Hotels;

public interface HotelsRepository extends JpaRepository<Hotels, Long> {

    @Query("SELECT h FROM Hotels h LEFT JOIN FETCH h.city LEFT JOIN FETCH h.state WHERE h.hotelid = :hotelid")
    Hotels findByIdWithDetails(@Param("hotelid") Long hotelid);

    @Query("SELECT h FROM Hotels h LEFT JOIN FETCH h.city LEFT JOIN FETCH h.state")
    List<Hotels> findAllWithDetails();
}
