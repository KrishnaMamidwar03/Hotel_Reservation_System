import React, { useState } from 'react';
import axios from 'axios';
import { Form, Button, Alert, Container, Row, Col } from 'react-bootstrap';
import './AdminAddHotel.css'; // Import custom CSS for additional styling

const AdminAddHotel = () => {
    const [hotel, setHotel] = useState({
        ownername: '',
        hotelname: '',
        cityCode: '',
        stateCode: ''
    });
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);

    // Hardcoded cities and states
    const cities = [
        { code: 'PUN', name: 'Pune' },
        { code: 'BLR', name: 'Bangalore' },
        { code: 'CHE', name: 'Chennai' },
        { code: 'NDL', name: 'New Delhi' }
    ];

    const states = [
        { code: 'MH', name: 'Maharashtra' },
        { code: 'KA', name: 'Karnataka' },
        { code: 'TN', name: 'Tamil Nadu' },
        { code: 'DL', name: 'Delhi' }
    ];

    const handleChange = (e) => {
        setHotel({ ...hotel, [e.target.name]: e.target.value });
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        axios.post('http://localhost:8080/admin/addhotel', hotel)
            .then(response => {
                setSuccess('Hotel added successfully');
                setError(null);
                setHotel({
                    ownername: '',
                    hotelname: '',
                    cityCode: '',
                    stateCode: ''
                });
            })
            .catch(error => setError('Failed to add hotel'));
    };

    return (
        <Container className="mt-5">
            <h2 className="mb-4 text-center">Add New Hotel</h2>
            {error && <Alert variant="danger">{error}</Alert>}
            {success && <Alert variant="success">{success}</Alert>}
            <Form onSubmit={handleSubmit} className="shadow-lg p-4 rounded form-border">
                <Row className="mb-3">
                    <Form.Group as={Col} controlId="formOwnerName">
                        <Form.Label>Owner Name</Form.Label>
                        <Form.Control
                            type="text"
                            name="ownername"
                            placeholder="Enter the owner's name"
                            value={hotel.ownername}
                            onChange={handleChange}
                        />
                    </Form.Group>
                </Row>
                <Row className="mb-3">
                    <Form.Group as={Col} controlId="formHotelName">
                        <Form.Label>Hotel Name</Form.Label>
                        <Form.Control
                            type="text"
                            name="hotelname"
                            placeholder="Enter the hotel name"
                            value={hotel.hotelname}
                            onChange={handleChange}
                        />
                    </Form.Group>
                </Row>
                <Row className="mb-3">
                    <Form.Group as={Col} controlId="formCity">
                        <Form.Label>City</Form.Label>
                        <Form.Control
                            as="select"
                            name="cityCode"
                            value={hotel.cityCode}
                            onChange={handleChange}
                        >
                            <option value="">Select City</option>
                            {cities.map(city => (
                                <option key={city.code} value={city.code}>
                                    {city.name}
                                </option>
                            ))}
                        </Form.Control>
                    </Form.Group>
                </Row>
                <Row className="mb-4">
                    <Form.Group as={Col} controlId="formState">
                        <Form.Label>State</Form.Label>
                        <Form.Control
                            as="select"
                            name="stateCode"
                            value={hotel.stateCode}
                            onChange={handleChange}
                        >
                            <option value="">Select State</option>
                            {states.map(state => (
                                <option key={state.code} value={state.code}>
                                    {state.name}
                                </option>
                            ))}
                        </Form.Control>
                    </Form.Group>
                </Row>
                <Button variant="success" type="submit" className="w-100">Add Hotel</Button>
            </Form>
        </Container>
    );
};

export default AdminAddHotel;
