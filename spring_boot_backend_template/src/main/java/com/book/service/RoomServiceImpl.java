package com.book.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.book.entities.Room;
import com.book.repository.RoomRepository;

@Service
public class RoomServiceImpl implements RoomService {

	@Autowired
	private RoomRepository roomRepository;

	@Override
	public List<Room> findRoomsByHotelId(Long hotelId) {
		return roomRepository.findByHotel_Hotelid(hotelId);
	}

	@Override
	public Optional<Room> findById(Long roomId) {
		return roomRepository.findById(roomId);

	}

}
