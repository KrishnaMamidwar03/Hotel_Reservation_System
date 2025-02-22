import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import "./loginbag.css"

const LoginPage = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('http://localhost:8080/auth/login', {
        email,
        password
      }, {
        headers: {
          'Content-Type': 'application/json',
        },
      });

      // if (response.status === 200) {
      //   setSuccess(response.data.message);
      //   setError('');

      //   // Store user data in session storage
      //   sessionStorage.setItem('user', JSON.stringify(response.data.user));

      //   // Navigate to the customer profile page
      //   navigate('/customer');
      if (response.status === 200) {
        const { user, message } = response.data;
        setSuccess(message);
        setError('');

        // Store user data in session storage
        sessionStorage.setItem('user', JSON.stringify(user));

        // Navigate based on user role
        if (user.role === 'ADMIN') {
          navigate('/admin');
        } else {
          navigate('/customer');
        }
      }
    } catch (err) {
      setError(err.response?.data?.message || 'An error occurred');
      setSuccess('');
    }
  };

  return (
    <div className="bgcontainer">
      <div className="  container mx-auto flex flex-col items-center justify-center py-16 px-16 ">
        <h2 className="text-3xl font-serif font-bold text-black mb-3">Login</h2>
        {error && <p className="text-red-500 mb-4">{error}</p>}
        {success && <p className="text-green-500 mb-4">{success}</p>}
        <form onSubmit={handleSubmit} className="space-y-4 w-full max-w-md">
          <div>
            <label htmlFor="email" className="block text-lg font-bold text-black mb-3">Email:</label>
            <input
              type="email"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-dark"
              required
            />
          </div>
          <div>
            <label htmlFor="password" className="block text-lg font-bold text-black mb-3">Password:</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-dark"
              required
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 bg-primary-dark text-white font-bold rounded-md hover:bg-primary-dark-dark"
          >
            Login
          </button>
        </form>
      </div>
    </div>
  );
};

export default LoginPage;


