//package com.book.controller;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.web.bind.annotation.DeleteMapping;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.PathVariable;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.PutMapping;
//import org.springframework.web.bind.annotation.RequestBody;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
//
//import com.book.DTO.HotelDto;
//import com.book.entities.Bookings;
//import com.book.service.AdminService;
//import com.book.service.CustomerService;
//
//import java.util.List;
//
//@RestController
//@RequestMapping("/admin")
//public class AdminController {
//
//    @Autowired
//    private AdminService adminService;
//    
//    @Autowired
//    private CustomerService bookingService;
//
//    @GetMapping("/bookings")
//    public List<Bookings> getAllBookings() {
//        return bookingService.getAllBookings();
//    }
//
//    @GetMapping
//    public List<HotelDto> getAllHotels() {
//        return adminService.getAllHotels();
//    }
//
//    @GetMapping("/{hotelId}")
//    public HotelDto getHotelById(@PathVariable Long hotelId) {
//        return adminService.getHotelById(hotelId);
//    }
//
//    @PostMapping
//    public HotelDto addHotel(@RequestBody HotelDto hotelDto) {
//        return adminService.addHotel(hotelDto);
//    }
//    
//    @PutMapping("/{hotelId}")
//    public HotelDto updateHotel(@PathVariable Long hotelId, @RequestBody HotelDto hotelDto) {
//    	return adminService.updateHotel(hotelId, hotelDto);
//    }
//
//    @DeleteMapping("/{hotelId}")
//    public void deleteHotel(@PathVariable Long hotelId) {
//        adminService.deleteHotel(hotelId);
//    }
//}
//
package com.book.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.book.DTO.AdminBookingDto;
import com.book.DTO.AdminHotelDto;
import com.book.DTO.HotelsDTO;
import com.book.entities.City;
import com.book.entities.Hotels;
import com.book.entities.State;
import com.book.service.AdminBookingService;
import com.book.service.CitiesService;
import com.book.service.HotelService;
import com.book.service.HotelsService;
import com.book.service.StatesService;

@RestController
@RequestMapping("/admin")
@CrossOrigin
public class AdminController {

    @Autowired
    private HotelService hotelService;
    @Autowired
    private AdminBookingService bookingService;

    @GetMapping("/{hotelid}")
    public ResponseEntity<AdminHotelDto> getHotelById(@PathVariable Long hotelid) {
        AdminHotelDto dto = hotelService.getHotelById(hotelid);
        return ResponseEntity.ok(dto);
    }

    @GetMapping("/allhotel")
    public ResponseEntity<List<AdminHotelDto>> getAllHotels() {
        List<AdminHotelDto> hotels = hotelService.getAllHotels();
        return ResponseEntity.ok(hotels);
    }
   

    @GetMapping("/getbooking")
    public List<AdminBookingDto> getAllBookings() {
        return bookingService.getAllBookings();
    }
    @Autowired
    private HotelsService hotelsService;

    @Autowired
    private CitiesService cityService;

    @Autowired
    private StatesService stateService;

    @PostMapping("/addhotel")
    public ResponseEntity<Hotels> addHotel(@RequestBody HotelsDTO hotelDTO) {
        City city = cityService.findByCode(hotelDTO.getCityCode())
            .orElseThrow(() -> new RuntimeException("City not found"));
        State state = stateService.findByCode(hotelDTO.getStateCode())
            .orElseThrow(() -> new RuntimeException("State not found"));

        Hotels hotel = new Hotels();
        hotel.setOwnername(hotelDTO.getOwnername());
        hotel.setHotelname(hotelDTO.getHotelname());
        hotel.setCity(city);
        hotel.setState(state);

        Hotels savedHotel = hotelsService.saveHotel(hotel);

        return ResponseEntity.ok(savedHotel);
    }
}

