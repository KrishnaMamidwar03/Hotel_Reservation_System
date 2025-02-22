import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const SignUpPage = () => {
  const [formData, setFormData] = useState({
    firstname: '',
    lastname: '',
    password: '',
    rePassword: '', // Field for re-entering password
    email: '',
    phone: '',
    role: 'CUSTOMER', // Default role set to CUSTOMER
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prevData) => ({
      ...prevData,
      [name]: value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (formData.password !== formData.rePassword) {
      setError('Passwords do not match');
      return;
    }

    try {
      const url = 'http://localhost:8080/auth/register';
      const response = await axios.post(url, formData, {
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (response.status === 200) {
        setSuccess(response.data.message);
        setError('');
        navigate('/login'); // Redirect to login page after successful registration
      }
    } catch (err) {
      setError(err.response?.data?.message || 'An error occurred');
      setSuccess('');
    }
  };

  return (
    <div className='bgcontainer'>
    <div className=" container mx-auto flex flex-col items-center justify-center py-16 px-4">
      {error && (
        <div className="bg-red-500 text-white text-center p-3 rounded mb-4">
          {error}
        </div>
      )}
      {success && (
        <div className="bg-green-500 text-white text-center p-3 rounded mb-4">
          {success}
        </div>
      )}
      <form onSubmit={handleSubmit} className="space-y-4 w-full max-w-md">
        <div>
          <label htmlFor="firstname" className="block text-lg font-bold text-black mb-3">First Name:</label>
          <input
            type="text"
            id="firstname"
            name="firstname"
            value={formData.firstname}
            onChange={handleChange}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-dark"
            required
          />
        </div>

        <div>
          <label htmlFor="lastname" className="block text-lg font-bold text-black mb-3">Last Name:</label>
          <input
            type="text"
            id="lastname"
            name="lastname"
            value={formData.lastname}
            onChange={handleChange}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-dark"
            required
          />
        </div>

        <div>
          <label htmlFor="phone" className="block text-lg font-bold text-black mb-3">Phone:</label>
          <input
            type="tel"
            id="phone"
            name="phone"
            value={formData.phone}
            onChange={handleChange}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-dark"
            required
          />
        </div>

        <div>
          <label htmlFor="email" className="block text-lg font-bold text-black mb-3">Email:</label>
          <input
            type="email"
            id="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-dark"
            required
          />
        </div>

        <div>
          <label htmlFor="password" className="block text-lg font-bold text-black mb-3">Password:</label>
          <input
            type="password"
            id="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-dark"
            required
          />
        </div>

        <div>
          <label htmlFor="rePassword" className="block text-lg font-bold text-black mb-3">Re-enter Password:</label>
          <input
            type="password"
            id="rePassword"
            name="rePassword"
            value={formData.rePassword}
            onChange={handleChange}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-dark"
            required
          />
        </div>

        <button
          type="submit"
          className="w-full py-2 bg-primary-dark text-white font-bold rounded-md hover:bg-primary-dark-dark"
        >
          Register
        </button>
      </form>
    </div>
  </div>
  );
};

export default SignUpPage;
