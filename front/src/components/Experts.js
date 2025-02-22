import React from 'react';

function Experts() {
  return (
    <div className="container mx-auto px-4 py-16">
      <h2 className="text-4xl font-serif font-bold text-primary-dark mb-6 text-center">
        Our Experts
      </h2>
      <ul className="list-disc pl-5 space-y-4 text-lg text-gray-700 max-w-2xl mx-auto">
        <li>Dr. Sheetal</li>
        <li>Dr. Sharma</li>
        <li>Dr. Kapoor</li>
      </ul>
    </div>
  );
}

export default Experts;
