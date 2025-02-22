package com.book.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.book.entities.City;
import com.book.repository.CityRepository;

@Service
public class CitiesService {

    @Autowired
    private CityRepository cityRepository;

    public Optional<City> findByCode(String code) {
        return cityRepository.findById(code);
    }
}

