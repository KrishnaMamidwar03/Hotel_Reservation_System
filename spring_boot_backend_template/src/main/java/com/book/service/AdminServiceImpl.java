package com.book.service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.transaction.Transactional;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.book.DTO.HotelDto;
import com.book.entities.Hotels;
import com.book.entities.Room;
import com.book.repository.HotelRepository;
import com.book.repository.RoomRepository;

@Service
public class AdminServiceImpl implements AdminService{
	
	
	@Autowired
    private HotelRepository hotelRepository;

	@Autowired
    private RoomRepository roomRepository;
	
//	@Autowired
//    private LocationRepository locationRepository;
	
    @Autowired
    private ModelMapper modelMapper;
    
    @Override
    public List<HotelDto> getAllHotels() {
        List<Hotels> hotels = hotelRepository.findAll();
        return hotels.stream()
                .map(hotel -> {
                    HotelDto hotelDto = modelMapper.map(hotel, HotelDto.class);
//                    hotelDto.setNumberofrooms(hotel.getRoom().getNumberofrooms());
//                    hotelDto.setRoomtype(hotel.getRoom().getRoomtype());
//                    hotelDto.setPriceperday(hotel.getRoom().getPriceperday());
//                    hotelDto.setCity(hotel.getLocations().getCity());
//                    hotelDto.setState(hotel.getLocations().getState());
                    return hotelDto;
                })
                .collect(Collectors.toList());
    }
    
    @Override
    public HotelDto getHotelById(Long hotelid) {
        Optional<Hotels> hotelOpt = hotelRepository.findById(hotelid);
        if (hotelOpt.isPresent()) {
            Hotels hotel = hotelOpt.get();
            HotelDto hotelDto = modelMapper.map(hotel, HotelDto.class);
//            hotelDto.setNumberofrooms(hotel.getRoom().getNumberofrooms());
//            hotelDto.setRoomtype(hotel.getRoom().getRoomtype());
//            hotelDto.setPriceperday(hotel.getRoom().getPriceperday());
//            hotelDto.setCity(hotel.getLocations().getCity());
//            hotelDto.setState(hotel.getLocations().getState());
            return hotelDto;
        }
        return null; // Handle not found case as needed
    }
    
    @Override
    public HotelDto addHotel(HotelDto hotelDto) {
        // Add Location
//        Locations location = modelMapper.map(hotelDto, Locations.class);
//        Locations savedLocation = locationRepository.save(location);

        // Add Room
        Room room = modelMapper.map(hotelDto, Room.class);
        Room savedRoom = roomRepository.save(room);

        // Add Hotel
        Hotels hotel = modelMapper.map(hotelDto, Hotels.class);
        hotel.setOwnername(hotelDto.getOwnername());
        hotel.setHotelname(hotelDto.getHotelname());
//        hotel.setLocations(savedLocation);   
//        hotel.setRoom(savedRoom);
        Hotels savedHotel = hotelRepository.save(hotel);

        // Update DTO with saved entities
        hotelDto.setHotelid(savedHotel.getHotelid());
        return hotelDto;
    }

//	 @Override
//	    public void deleteHotel(Long id) {
//	        Optional<Hotels> hotelOptional = hotelRepository.findById(id);
//	        if (hotelOptional.isPresent()) {
//	            Hotels hotel = hotelOptional.get();
//	            roomRepository.deleteById(hotel.getRoom().getRoomid());
//	            locationRepository.deleteById(hotel.getLocations().getLocationid());
//	            hotelRepository.deleteById(id);
//	        } else {
//	            throw new RuntimeException("Hotel not found with id: " + id);
//	        }
//	    }
    
//    @Override
//    public HotelDto updateHotel(Long hotelid, HotelDto hotelDto) {
//        Optional<Hotels> hotelOpt = hotelRepository.findById(hotelid);
//        if (hotelOpt.isPresent()) {
//            Hotels existingHotel = hotelOpt.get();
//            modelMapper.map(hotelDto, existingHotel); // Update fields
//            existingHotel = hotelRepository.save(existingHotel);
//            return modelMapper.map(existingHotel, HotelDto.class);
//        }
//        return null; // Handle not found case as needed
//    }
    
    @Override
    public HotelDto updateHotel(Long hotelid, HotelDto hotelDto) {
        Optional<Hotels> hotelOpt = hotelRepository.findById(hotelid);
        if (hotelOpt.isPresent()) {
            Hotels existingHotel = hotelOpt.get();

            // Update Location
//            Locations existingLocation = existingHotel.getLocations();
//            modelMapper.map(hotelDto, existingLocation);
//            Locations updatedLocation = locationRepository.save(existingLocation);

            // Update Room
//            Room existingRoom = existingHotel.getRoom();
//            modelMapper.map(hotelDto, existingRoom);
//            Room updatedRoom = roomRepository.save(existingRoom);

            // Update Hotel
            existingHotel.setOwnername(hotelDto.getOwnername());
            existingHotel.setHotelname(hotelDto.getHotelname());
//            existingHotel.setLocations(updatedLocation);
//            existingHotel.setRoom(updatedRoom);

            Hotels updatedHotel = hotelRepository.save(existingHotel);

            return modelMapper.map(updatedHotel, HotelDto.class);
        }
        return null; // Handle not found case as needed
    }
    
    @Override
    @Transactional
    public void deleteHotel(Long id) {
        Optional<Hotels> hotelOptional = hotelRepository.findById(id);
        if (hotelOptional.isPresent()) {
            Hotels hotel = hotelOptional.get();
            
            // Delete the associated room
//            if (hotel.getRoom() != null) {
//                roomRepository.deleteById(hotel.getRoom().getRoomid());
//            }

//            // Delete the associated location
//            if (hotel.getLocations() != null) {
////                locationRepository.deleteById(hotel.getLocations().getLocationid());
//            }

            // Delete the hotel itself
            hotelRepository.deleteById(id);
        } else {
            throw new RuntimeException("Hotel not found with id: " + id);
        }
    }
	    
}
