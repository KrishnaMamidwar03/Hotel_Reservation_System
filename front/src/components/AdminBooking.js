// // src/components/BookingTable.js
// import React, { useEffect, useState } from 'react';
// import axios from 'axios';
// import { Table } from 'react-bootstrap';
// import './AdminPage.css';

// const AdminBooking = () => {
//   const [bookings, setBookings] = useState([]);
//   const [error, setError] = useState(null); 

//   useEffect(() => {
//     axios.get('http://localhost:8080/admin/getbooking') 
//       .then(response => {
//         setBookings(response.data);
//       })
//       .catch(error => {
//         console.error('Error fetching booking data:', error);
//         setError('Error fetching data'); 
//       });
//   }, []);

//   return (
//     <div className="container mt-4">
//         <br/><br/><br/>
//       <h2>Bookings</h2>
//       {error && <div className="alert alert-danger">{error}</div>} 
//       <Table striped bordered hover className="mt-3">
//         <thead>
//           <tr>
//             <th>Booking ID</th>
//             <th>First Name</th>
//             <th>Last Name</th>
//             <th>Hotel Name</th>
//             <th>City</th>
//             <th>Room Type</th>
//             <th>Check-in Date</th>
//             <th>Check-out Date</th>
//           </tr>
//         </thead>
//         <tbody>
//           {bookings.map(booking => (
//             <tr key={booking.bookingid}>
//               <td>{booking.bookingid}</td>
//               <td>{booking.firstname}</td>
//               <td>{booking.lastname}</td>
//               <td>{booking.hotelname}</td>
//               <td>{booking.city}</td>
//               <td>{booking.roomtype}</td>
//               <td>{new Date(booking.checkindate).toLocaleDateString()}</td>
//               <td>{new Date(booking.checkoutdate).toLocaleDateString()}</td>
//             </tr>
//           ))}
//         </tbody>
//       </Table>
//     </div>
//   );
// };

// export default AdminBooking;


// src/components/BookingTable.js
import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Table, Container, Alert } from 'react-bootstrap';
import './AdminPage.css';

const AdminBooking = () => {
  const [bookings, setBookings] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios.get('http://localhost:8080/admin/getbooking')
      .then(response => {
        setBookings(response.data);
      })
      .catch(error => {
        console.error('Error fetching booking data:', error);
        setError('Error fetching data');
      });
  }, []);

  return (
    <Container className="mt-4">
      <br/><br/><br/>
      <h2 className="text-left mb-4 display-3 font-weight-bold text-purple heading-border">Customer Bookings</h2>

     {error && <Alert variant="danger">{error}</Alert>}
      <Table striped bordered hover className="booking-table">
        <thead>
          <tr>
            <th>Booking ID</th>
            <th>First Name</th>
            <th>Last Name</th>
            <th>Hotel Name</th>
            <th>City</th>
            <th>Room Type</th>
            <th>Check-in Date</th>
            <th>Check-out Date</th>
          </tr>
        </thead>
        <tbody>
          {bookings.map(booking => (
            <tr key={booking.bookingid}>
              <td>{booking.bookingid}</td>
              <td>{booking.firstname}</td>
              <td>{booking.lastname}</td>
              <td>{booking.hotelname}</td>
              <td>{booking.city}</td>
              <td>{booking.roomtype}</td>
              <td>{new Date(booking.checkindate).toLocaleDateString()}</td>
              <td>{new Date(booking.checkoutdate).toLocaleDateString()}</td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Container>
  );
};

export default AdminBooking;
