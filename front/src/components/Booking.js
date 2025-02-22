import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './Booking.css'; // Ensure you have this CSS file

function Booking() {
  const [locations, setLocations] = useState(['Mumbai', 'Pune']);
  const [hotels, setHotels] = useState([]);
  const [rooms, setRooms] = useState(['Single', 'Double', 'Suite']);
  const [selectedLocation, setSelectedLocation] = useState('');
  const [selectedHotel, setSelectedHotel] = useState('');
  const [selectedRoom, setSelectedRoom] = useState('');
  const [bookingDetails, setBookingDetails] = useState(null);

  useEffect(() => {
    if (selectedLocation) {
      axios.get(`/api/hotels?location=${selectedLocation}`)
        .then(response => setHotels(response.data))
        .catch(error => console.error(error));
    }
  }, [selectedLocation]);

  const handleBooking = () => {
    axios.post('/api/bookings', {
      location: selectedLocation,
      hotel: selectedHotel,
      roomType: selectedRoom
    })
    .then(response => {
      setBookingDetails({
        location: selectedLocation,
        hotel: selectedHotel,
        roomType: selectedRoom
      });
      alert('Booking successful');
    })
    .catch(error => console.error('Booking failed:', error));
  };

  return (
    <div className="booking-container">
      <h1>Hotel Booking System</h1>
      <div>
        <label>Location:</label>
        <select onChange={e => setSelectedLocation(e.target.value)} value={selectedLocation}>
          <option value="">Select Location</option>
          {locations.map(location => (
            <option key={location} value={location}>{location}</option>
          ))}
        </select>
      </div>

      <div>
        <label>Hotel:</label>
        <select onChange={e => setSelectedHotel(e.target.value)} value={selectedHotel} disabled={!selectedLocation}>
          <option value="">Select Hotel</option>
          {hotels.map(hotel => (
            <option key={hotel} value={hotel}>{hotel}</option>
          ))}
        </select>
      </div>

      <div>
        <label>Room Type:</label>
        <select onChange={e => setSelectedRoom(e.target.value)} value={selectedRoom} disabled={!selectedHotel}>
          <option value="">Select Room Type</option>
          {rooms.map(room => (
            <option key={room} value={room}>{room}</option>
          ))}
        </select>
      </div>

      <button onClick={handleBooking} disabled={!selectedRoom}>Book Now</button>

      {bookingDetails && (
        <div className="booking-details">
          <h2>Booking Details</h2>
          <table>
            <thead>
              <tr>
                <th>Hotel Name</th>
                <th>Location</th>
                <th>Room Type</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>{bookingDetails.hotel}</td>
                <td>{bookingDetails.location}</td>
                <td>{bookingDetails.roomType}</td>
              </tr>
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default Booking;
