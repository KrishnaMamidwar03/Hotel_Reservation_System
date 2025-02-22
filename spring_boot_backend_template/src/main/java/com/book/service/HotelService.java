package com.book.service;

import java.util.List;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.book.DTO.AdminHotelDto;
import com.book.DTO.CityDto;
import com.book.DTO.StateDto;
import com.book.entities.Hotels;
import com.book.repository.HotelsRepository;

@Service
public class HotelService {

    @Autowired
    private HotelsRepository hotelsRepository;

    @Autowired
    private ModelMapper modelMapper;

    public AdminHotelDto getHotelById(Long hotelid) {
        Hotels hotel = hotelsRepository.findByIdWithDetails(hotelid);
        return mapToDto(hotel);
    }

    public List<AdminHotelDto> getAllHotels() {
        List<Hotels> hotels = hotelsRepository.findAllWithDetails();
        return hotels.stream().map(this::mapToDto).collect(Collectors.toList());
    }

    private AdminHotelDto mapToDto(Hotels hotel) {
        AdminHotelDto dto = modelMapper.map(hotel, AdminHotelDto.class);
        dto.setCity(modelMapper.map(hotel.getCity(), CityDto.class));
        dto.setState(modelMapper.map(hotel.getState(), StateDto.class));
        
        return dto;
    }
}
