package com.book.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.book.entities.Hotels;
import com.book.repository.HotelsRepository;

@Service
public class HotelsService {

    @Autowired
    private HotelsRepository hotelsRepository;

    public Hotels saveHotel(Hotels hotel) {
        return hotelsRepository.save(hotel);
    }
}

