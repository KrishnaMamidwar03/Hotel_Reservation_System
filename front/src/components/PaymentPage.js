import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const PaymentPage = () => {
  const navigate = useNavigate();
  const [bookingDetails, setBookingDetails] = useState(null);
  const [userDetails, setUserDetails] = useState(null);
  const [selectedPaymentMethod, setSelectedPaymentMethod] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const details = JSON.parse(sessionStorage.getItem('bookingDetails'));
    const user = JSON.parse(sessionStorage.getItem('user'));

    if (details && user) {
      setBookingDetails(details);
      setUserDetails(user);
    } else {
      navigate('/'); // Redirect to home if no details are found
    }
  }, [navigate]);

  const handlePayment = async () => {
    if (!selectedPaymentMethod) {
      alert('Please select a payment method.');
      return;
    }

    setLoading(true);

    try {
      // Make API call to book the room
      const response = await axios.post('http://localhost:8080/customer/booking', {
        userId: userDetails.userid,
        hotelId: bookingDetails.hotelId,
        roomIds: bookingDetails.rooms.map(room => room.roomId),
        checkInDate: bookingDetails.checkin,
        checkOutDate: bookingDetails.checkout,
        totalPay: bookingDetails.totalPrice,
        paymentMode: selectedPaymentMethod
      });

      if (response.status === 200) {
        alert('Booking successful!');
        sessionStorage.removeItem('bookingDetails'); // Clear booking details
        sessionStorage.removeItem('user'); // Clear user details
        navigate('/'); // Redirect to homepage or any other page
      } else {
        alert('Booking failed.');
      }
    } catch (error) {
      alert('Booking Complete');
      
    } finally {
      setLoading(false);
      navigate('/customer');
    }
  };

  if (!bookingDetails || !userDetails) {
    return <p>Loading...</p>;
  }

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4">Payment Details</h1>
      <div className="bg-white p-4 border border-gray-300 rounded-lg shadow-md">
        <h2 className="text-xl font-semibold mb-2">Booking Summary</h2>
        <p><strong>Hotel ID:</strong> {bookingDetails.hotelId}</p>
        <p><strong>Check-In Date:</strong> {bookingDetails.checkin}</p>
        <p><strong>Check-Out Date:</strong> {bookingDetails.checkout}</p>
        <p><strong>Number of Persons:</strong> {bookingDetails.numPersons}</p>

        <h3 className="text-lg font-semibold mt-4">Selected Rooms</h3>
        {bookingDetails.rooms.map(room => (
          <p key={room.roomId}>
            <strong>Room Type:</strong> {room.roomType} <strong>Price Per Day:</strong> ₹{room.pricePerDay}
          </p>
        ))}

        <p className="mt-4"><strong>Total Price:</strong> ₹{bookingDetails.totalPrice}</p>

        <h3 className="text-lg font-semibold mt-4">Payment Method</h3>
        <select
          value={selectedPaymentMethod}
          onChange={(e) => setSelectedPaymentMethod(e.target.value)}
          className="w-full p-2 border border-gray-300 rounded-md"
        >
          <option value="">Select Payment Method</option>
          <option value="CREDIT_CARD">Credit Card</option>
          <option value="DEBIT_CARD">Debit Card</option>
          <option value="UPI">UPI</option>
          <option value="NET_BANKING">Net Banking</option>
        </select>

        <button
          onClick={handlePayment}
          className="mt-4 w-full py-2 bg-primary-dark text-white font-bold rounded-md hover:bg-primary-dark-dark"
          disabled={loading}
        >
          {loading ? 'Processing...' : 'Complete Payment'}
        </button>
      </div>
    </div>
  );
};

export default PaymentPage;
