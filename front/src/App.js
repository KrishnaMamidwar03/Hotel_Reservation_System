import React from 'react';
import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
import NavBar from './components/NavBar/NavBar';
import HomePage from './components/HomePage';
import AboutUs from './components/AboutUs';
import Rooms from './components/Room';
import Reviews from './components/Reviews';
import Footer from './components/Footer';
import LoginPage from './components/LoginPage';
import ContactPage from './components/ContactPage';
import SignUpPage from './components/SignUpPage';
import Booking from './components/Booking';
import Customer from './components/CustomerPage';
import AdminHotelTable from './components/AdminHotelTable';
import HotelDetails from './components/HotelDetails';
import CustomerPage from './components/CustomerPage';
import PaymentPage from './components/PaymentPage';
import AdminBooking from './components/AdminBooking';
import AdminAddHotel from './components/AdminAddHotel';
function App() {
  return (
    <Router>
      <div className="min-h-screen pb-16">
        <NavBar />
        <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/about-us" element={<AboutUs />} />
        <Route path="/rooms" element={<Rooms />} />
        <Route path="/reviews" element={<Reviews />} />
        <Route path="/contact" element={<ContactPage />} />
        <Route path="/register" element={<SignUpPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/booking" element={<Booking />} />
        <Route path="/customer" element={<Customer />} />
        <Route path="/admin" element={<AdminHotelTable />} />
        <Route path="/allbookings" element={<AdminBooking />} />
        <Route path="/customerpage" element={<CustomerPage />} />
        <Route path="/hotel" element={<HotelDetails />} />
        <Route path="/addhotel" element={<AdminAddHotel/>} />
        <Route path="/payment" element={<PaymentPage />} />
        <Route path="*" element={<Navigate to="/" />} />
        </Routes>
        <Footer />
      </div>
    </Router>
  );
}

export default App;
