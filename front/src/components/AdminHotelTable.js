// import React, { useState, useEffect } from 'react';
// import axios from 'axios';
// import { Table, Container } from 'react-bootstrap';
// import './AdminPage.css';

// const AdminHotelTable = () => {
//   const [hotels, setHotels] = useState([]);
//   const [loading, setLoading] = useState(true);
//   const [error, setError] = useState(null);

//   useEffect(() => {
//     const fetchHotels = async () => {
//       try {
//         const response = await axios.get('http://localhost:8080/admin/allhotel'); // Replace with your API URL
//         setHotels(response.data);
//         setLoading(false);
//       } catch (err) {
//         setError(err.message);
//         setLoading(false);
//       }
//     };

//     fetchHotels();
//   }, []);

//   if (loading) return <p>Loading...</p>;
//   if (error) return <p>Error: {error}</p>;

//   return (
//     <div>
//         <br/><br/><br/>
//         <div className="container mx-auto flex justify-between items-center p-2">
//         <h1>WELCOME ADMIN</h1>
//         <h3><a href=''>hotel details</a></h3>
//         <h3><a href="">Customer Details</a></h3>
//         </div>

//     <Container className="hoteltable mt-4">
//       <h1>Hotel Details</h1>
//       <Table striped bordered hover >
//         <thead className="hotel-table">
//           <tr>
//             <th>Hotel ID</th>
//             <th>Owner Name</th>
//             <th>Hotel Name</th>
//             <th>City</th>
//             <th>State</th>
//           </tr>
//         </thead>
//         <tbody>
//           {hotels.map(hotel => (
//             <tr key={hotel.hotelid}>
//               <td>{hotel.hotelid}</td>
//               <td>{hotel.ownername}</td>
//               <td>{hotel.hotelname}</td>
//               <td>{hotel.city.name}</td> {/* Adjust according to the structure of CityDto */}
//               <td>{hotel.state.name}</td> {/* Adjust according to the structure of StateDto */}
//             </tr>
//           ))}
//         </tbody>
//       </Table>
//     </Container>

//     </div>
//   );
// };

// export default AdminHotelTable;



import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Table, Container } from 'react-bootstrap';
import './AdminPage.css';


const AdminHotelTable = () => {
  const [hotels, setHotels] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showTable, setShowTable] = useState(false); 
  const[bookings, setBookings]=useState(false);

  useEffect(() => {
    const fetchHotels = async () => {
      try {
        const response = await axios.get('http://localhost:8080/admin/allhotel');
        setHotels(response.data);
        setLoading(false);
      } catch (err) {
        setError(err.message);
        setLoading(false);
      }
    };

    fetchHotels();
  }, []);

  if (loading) return <p>Loading...</p>;
  if (error) return <p>Error: {error}</p>;

  return (
    <div >
        <br/><br/><br/>
        <div className="container mx-auto flex justify-between items-center p-2">
        <h1 className="text-center text-primary font-weight-bold">WELCOME ADMIN</h1>
  
          <h3><a href="#" onClick={() => setShowTable(true)}>Hotel Details</a></h3>
          <h3><a href="/allbookings" onClick={()=>setBookings(true)}>Customer Bookings</a></h3>
          <h3><a href="/addhotel" onClick={()=>setHotels(true)}>Add Hotel</a></h3>
        </div>

        <Container className="hoteltable mt-4">
          {showTable && (
            <>
              <h1>Hotel Details</h1>
              <Table striped bordered hover className='table border border-primary'>
                <thead className="hotel-table">
                  <tr>
                    <th>Hotel ID</th>
                    <th>Owner Name</th>
                    <th>Hotel Name</th>
                    <th>City</th>
                    <th>State</th>
                  </tr>
                </thead>
                <tbody>
                  {hotels.map(hotel => (
                    <tr key={hotel.hotelid}>
                      <td>{hotel.hotelid}</td>
                      <td>{hotel.ownername}</td>
                      <td>{hotel.hotelname}</td>
                      <td>{hotel.city.name}</td> {/* Adjust according to the structure of CityDto */}
                      <td>{hotel.state.name}</td> {/* Adjust according to the structure of StateDto */}
                    </tr>
                  ))}
                </tbody>
              </Table>
            </>
          )}
        </Container>
       
    </div>
  );
};

export default AdminHotelTable;
