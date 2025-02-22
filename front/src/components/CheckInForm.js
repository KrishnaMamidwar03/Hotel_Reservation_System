import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const CheckInForm = () => {
  const [formData, setFormData] = useState({
    checkin: '',
    checkout: '',
    numPersons: '',
    state: '',
    city: ''
  });
  const [hotels, setHotels] = useState([]);
  const [error, setError] = useState('');
  const [states, setStates] = useState([]);
  const [cities, setCities] = useState([]);
  const [submitted, setSubmitted] = useState(false);
  const [formErrors, setFormErrors] = useState({});
  
  const navigate = useNavigate();

  useEffect(() => {
    const fetchStates = async () => {
      try {
        const response = await axios.get('http://localhost:8080/customer/states');
        setStates(response.data);
      } catch (err) {
        setError(err.response?.data?.message || 'An error occurred while fetching states');
      }
    };

    fetchStates();
  }, []);

  useEffect(() => {
    const fetchCities = async () => {
      if (formData.state) {
        try {
          const response = await axios.get(`http://localhost:8080/customer/city/${formData.state}`);
          setCities(response.data);
        } catch (err) {
          setError(err.response?.data?.message || 'An error occurred while fetching cities');
        }
      } else {
        setCities([]);
      }
    };

    fetchCities();
  }, [formData.state]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prevData) => ({
      ...prevData,
      [name]: value,
    }));
    validateForm(name, value);
  };

  const validateForm = (name, value) => {
    let errors = {};
    const checkinDate = new Date(formData.checkin);
    const checkoutDate = new Date(formData.checkout);
    const today = new Date();

    if (name === 'checkin' || name === 'checkout') {
      if (name === 'checkin') {
        if (value && new Date(value) < today.setHours(0,0,0,0)) { // Allow check-in on the current day or later
          errors.checkin = 'Check-in date must be today or in the future.';
        } else {
          errors.checkin = '';
        }
      }

      if (name === 'checkout') {
        if (value && new Date(value) <= checkinDate) {
          errors.checkout = 'Check-out date must be after check-in date.';
        } else {
          errors.checkout = '';
        }
      }
    }

    setFormErrors(errors);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const checkinDate = new Date(formData.checkin);
    const checkoutDate = new Date(formData.checkout);

    if (checkinDate < new Date().setHours(0,0,0,0)) {
      setFormErrors({ ...formErrors, checkin: 'Check-in date must be today or in the future.' });
      return;
    }

    if (checkoutDate <= checkinDate) {
      setFormErrors({ ...formErrors, checkout: 'Check-out date must be after check-in date.' });
      return;
    }

    try {
      const response = await axios.get(`http://localhost:8080/customer/hotels?state=${formData.state}&city=${formData.city}`);
      setHotels(response.data);
      setError('');
      setSubmitted(true);
    } catch (err) {
      setError(err.response?.data?.message || 'An error occurred');
    }
  };

  const handleBookClick = (hotel) => {
    sessionStorage.setItem('selectedHotel', JSON.stringify({
      ...hotel,
      checkin: formData.checkin,
      checkout: formData.checkout,
      numPersons: formData.numPersons
    }));
    navigate("/hotel");
  };

  return (
    <div className="text-gray-800 p-4">
      {!submitted ? (
        <form onSubmit={handleSubmit} className="space-y-4 max-w-lg mx-auto bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-2xl font-bold mb-4">Search Hotels</h2>
          <div>
            <label htmlFor="checkin" className="block text-lg text-gray-700">Check-In Date:</label>
            <input
              type="date"
              id="checkin"
              name="checkin"
              value={formData.checkin}
              onChange={handleChange}
              className={`mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 ${formErrors.checkin ? 'border-red-500' : 'focus:ring-primary-dark'}`}
              min={new Date().toISOString().split('T')[0]} // Allow today and future dates
              required
            />
            {formErrors.checkin && <p className="text-red-500 mt-1">{formErrors.checkin}</p>}
          </div>
          <div>
            <label htmlFor="checkout" className="block text-lg text-gray-700">Check-Out Date:</label>
            <input
              type="date"
              id="checkout"
              name="checkout"
              value={formData.checkout}
              onChange={handleChange}
              className={`mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 ${formErrors.checkout ? 'border-red-500' : 'focus:ring-primary-dark'}`}
              min={formData.checkin || new Date().toISOString().split('T')[0]} // Disable dates before check-in
              required
            />
            {formErrors.checkout && <p className="text-red-500 mt-1">{formErrors.checkout}</p>}
          </div>
          <div>
            <label htmlFor="numPersons" className="block text-lg text-gray-700">Number of Persons:</label>
            <input
              type="number"
              id="numPersons"
              name="numPersons"
              value={formData.numPersons}
              onChange={handleChange}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-dark"
              required
            />
          </div>
          <div>
            <label htmlFor="state" className="block text-lg text-gray-700">State:</label>
            <select
              id="state"
              name="state"
              value={formData.state}
              onChange={handleChange}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-dark"
              required
            >
              <option value="">Select State</option>
              {states.map((state) => (
                <option key={state.code} value={state.code}>{state.name}</option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="city" className="block text-lg text-gray-700">City:</label>
            <select
              id="city"
              name="city"
              value={formData.city}
              onChange={handleChange}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-dark"
              required
              disabled={!formData.state} // Disable until a state is selected
            >
              <option value="">Select City</option>
              {cities.length ? (
                cities.map((city) => (
                  <option key={city.code} value={city.code}>{city.name}</option>
                ))
              ) : (
                <option value="" disabled>No cities available</option>
              )}
            </select>
          </div>
          <button
            type="submit"
            className="w-full py-2 bg-primary-dark text-white font-bold rounded-md hover:bg-primary-dark-dark"
          >
            Search Hotels
          </button>
          {error && <p className="text-red-500 mt-4">{error}</p>}
        </form>
       ) : (
        <div className="mt-6 max-w-3xl mx-auto">
          <h3 className="text-2xl font-bold mb-4">Available Hotels:</h3>
          {hotels.length > 0 ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
              {hotels.map((hotel) => (
                <div key={hotel.hotelid} className="p-4 bg-white border border-gray-300 rounded-lg shadow-md">
                  <h4 className="text-xl font-semibold mb-2">{hotel.hotelname}</h4>
                  <p><strong>Owner:</strong> {hotel.ownername}</p>
                  <p><strong>Location:</strong> {hotel.city}, {hotel.state}</p>
                  <button 
                    className="mt-4 py-2 px-4 bg-primary-dark text-white rounded-md hover:bg-primary-dark-dark"
                    onClick={() => handleBookClick(hotel)}
                  >
                    Book
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <p>No hotels found for the selected criteria.</p>
          )}
        </div>
      )}
    </div>
  );
};

export default CheckInForm;
