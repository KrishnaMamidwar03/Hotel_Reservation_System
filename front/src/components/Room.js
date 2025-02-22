import React from "react";

function Rooms() {
  return (
    <div className="container mx-auto px-4 py-16">
      <h2 className="text-4xl font-serif font-bold text-yellow-500 mb-6 text-center">
        Our Rooms
      </h2>
      <ul className="list-disc pl-5 space-y-4 text-lg text-gray-200 max-w-2xl mx-auto">
        <li>Deluxe Rooms</li>
        <li>Executive Suites</li>
        <li>Family Rooms</li>
        <li>Luxury Villas</li>
      </ul>
    </div>
  );
}

export default Rooms;
