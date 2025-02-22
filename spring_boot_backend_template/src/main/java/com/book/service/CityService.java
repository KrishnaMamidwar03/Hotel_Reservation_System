package com.book.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.book.entities.City;
import com.book.repository.CityRepository;

@Service
public class CityService {

    @Autowired
    private CityRepository cityRepository;

    public List<City> getCitiesByStateCode(String stateCode) {
        return cityRepository.findByStateCode(stateCode);
    }

    public City createOrUpdateCity(City city) {
        return cityRepository.save(city);
    }
}
