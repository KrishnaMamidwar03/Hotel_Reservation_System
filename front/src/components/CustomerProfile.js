import React, { useEffect, useState } from 'react';
import axios from 'axios';

const isFutureBooking = (bookingDate) => {
  const now = new Date();
  return new Date(bookingDate) > now;
};

const CustomerProfile = () => {
  const [userData, setUserData] = useState(null);
  const [bookings, setBookings] = useState([]);

  useEffect(() => {
    // Retrieve user data from session storage
    const storedUserData = JSON.parse(sessionStorage.getItem('user'));
    if (storedUserData) {
      setUserData(storedUserData);
  
      // Fetch bookings for the user
      axios.get(`http://localhost:8080/customer/booking/${storedUserData.userid}`)
        .then(response => {
          setBookings(response.data);
          console.log(response.data); // For debugging
        })
        .catch(error => {
          console.error("Error fetching bookings:", error.response ? error.response.data : error.message);
        });
    }
  }, []);

  const handleCancelBooking = (bookingId) => {
    axios.delete(`http://localhost:8080/customer/booking/${bookingId}`)
      .then(() => {
        // Update the bookings state after successful cancellation
        setBookings(bookings.filter(booking => booking.bookingid !== bookingId));
      })
      .catch(error => {
        console.error("Error canceling booking:", error.response ? error.response.data : error.message);
      });
  };

  if (!userData) {
    return <div>Loading...</div>;
  }

  return (
    <div className="p-4 grid gap-6 md:grid-cols-2">
      <div className="mb-6">
        <p><strong>First Name:</strong> {userData.firstname}</p>
        <p><strong>Last Name:</strong> {userData.lastname}</p>
        <p><strong>Email:</strong> {userData.email}</p>
        <p><strong>Phone:</strong> {userData.phone}</p>
      </div>

      <div className='shadow-lg p-3 mb-5 bg-white rounded'>
        <h2 className="text-xl font-semibold mb-4">My Bookings</h2>
        {bookings.length === 0 ? (
          <p>No bookings found.</p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {bookings.map(booking => (
              <div
                key={booking.bookingid}
                className="bg-white shadow-lg rounded-lg p-4 flex flex-col"
              >
                <h3 className="text-lg font-semibold mb-2">{booking.hotel.hotelname}</h3>
                <p><strong>Check-in:</strong> {booking.checkindate}</p>
                <p><strong>Check-out:</strong> {booking.checkoutdate}</p>
                {isFutureBooking(booking.checkindate) && (
                  <button
                    onClick={() => handleCancelBooking(booking.bookingid)}
                    className="mt-4 bg-red-500 text-white py-2 px-4 rounded hover:bg-red-600"
                  >
                    Cancel Booking
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default CustomerProfile;
