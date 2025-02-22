package com.book.DTO;

import java.time.LocalDate;

public class AdminBookingDto {
    private Long bookingid;
    private String firstname;
    private String lastname;
    private String hotelname;
    private String city;
    private String roomtype;
    private LocalDate checkindate;
    private LocalDate checkoutdate;

    // Default constructor
    public AdminBookingDto() {}

    // Parameterized constructor
    public AdminBookingDto(Long bookingid, String firstname, String lastname, String hotelname, String city, String roomtype, LocalDate checkindate, LocalDate checkoutdate) {
        this.bookingid = bookingid;
        this.firstname = firstname;
        this.lastname = lastname;
        this.hotelname = hotelname;
        this.city = city;
        this.roomtype = roomtype;
        this.checkindate = checkindate;
        this.checkoutdate = checkoutdate;
    }

    // Getters and Setters
    public Long getBookingid() {
        return bookingid;
    }

    public void setBookingid(Long bookingid) {
        this.bookingid = bookingid;
    }

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getHotelname() {
        return hotelname;
    }

    public void setHotelname(String hotelname) {
        this.hotelname = hotelname;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getRoomtype() {
        return roomtype;
    }

    public void setRoomtype(String roomtype) {
        this.roomtype = roomtype;
    }

    public LocalDate getCheckindate() {
        return checkindate;
    }

    public void setCheckindate(LocalDate checkindate) {
        this.checkindate = checkindate;
    }

    public LocalDate getCheckoutdate() {
        return checkoutdate;
    }

    public void setCheckoutdate(LocalDate checkoutdate) {
        this.checkoutdate = checkoutdate;
    }
}
