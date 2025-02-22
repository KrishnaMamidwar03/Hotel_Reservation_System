package com.book.service;

import java.util.List;

import com.book.DTO.HotelDto;

public interface AdminService {
	
	List<HotelDto> getAllHotels();
    HotelDto getHotelById(Long hotelid);
    HotelDto addHotel(HotelDto hotelDto);
    void deleteHotel(Long hotelid);
    public HotelDto updateHotel(Long hotelid, HotelDto hotelDto);
}
