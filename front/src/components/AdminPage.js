import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './AdminPage.css'; // Ensure you have this CSS file
import AdminHotelTable from './AdminHotelTable';

const AdminPage = () => {
  const [hotels, setHotels] = useState([]);
  const [newHotel, setNewHotel] = useState({ name: '', location: '', rooms: 0 });

  useEffect(() => {
    axios.get('/api/admin/hotels')
      .then(response => setHotels(response.data))
      .catch(error => console.error(error));
  }, []);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setNewHotel(prevHotel => ({
      ...prevHotel,
      [name]: value
    }));
  };

  const handleAddHotel = () => {
    axios.post('/api/admin/hotels', newHotel)
      .then(response => {
        setHotels([...hotels, response.data]);
        setNewHotel({ name: '', location: '', rooms: 0 });
      })
      .catch(error => console.error('Error adding hotel:', error));
  };

  return (
    
    <div className="admin-container">
<br/><br/><br/>
      <h1>Admin Page</h1>
      <div>
        <h2>Add New Hotel</h2>
        <form className="hotel-form">
          <label htmlFor="name">Hotel Name:</label>
          <input type="text" id="name" name="name" value={newHotel.name} onChange={handleInputChange} />

          <label htmlFor="location">Location:</label>
          <input type="text" id="location" name="location" value={newHotel.location} onChange={handleInputChange} />

          <label htmlFor="rooms">Number of Rooms:</label>
          <input type="number" id="rooms" name="rooms" value={newHotel.rooms} onChange={handleInputChange} />

          <button type="button" onClick={handleAddHotel}>Add Hotel</button>
        </form>
      </div>
<AdminHotelTable/>
      <div>
        <h2>Hotel List</h2>
        <table className="hotel-table" >
          <thead>
            <tr>
              <th>Hotel Name</th>
              <th>Location</th>
              <th>Number of Rooms</th>
            </tr>
          </thead>
          <tbody>
            {hotels.map(hotel => (
              <tr key={hotel.id}>
                <td>{hotel.name}</td>
                <td>{hotel.location}</td>
                <td>{hotel.rooms}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AdminPage;


