import React from 'react';
import CustomerProfile from './CustomerProfile';
import CheckInForm from './CheckInForm';
import Card from './Card '; // Ensure you have this import
import avatarImg from '../images/profilepicture.jpeg';
import checkImg from '../images/checkin.jpeg';

const CustomerPage = () => {
  return (
    <div className="container mx-auto my-16 py-16 px-4">
      <div className="grid gap-6 md:grid-cols-1">
        <Card 
          title="Customer Profile" 
          description={<CustomerProfile />} 
          imgSrc={avatarImg} 
        />
        <Card 
          title="Check-In Desk" 
          description={<CheckInForm />} 
          imgSrc={checkImg} 
        />
      </div>
    </div>
  );
};

export default CustomerPage;
