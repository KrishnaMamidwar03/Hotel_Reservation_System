import React from 'react';

function Card({ title, description, imgSrc }) {
  return (
    <div className="bg-white border border-gray-200 rounded-lg shadow-lg hover:shadow-xl transition-shadow duration-300 transform hover:scale-105 p-4">
      {imgSrc && (
        <div className="relative w-full h-32">
          <img
            src={imgSrc}
            alt={title}
            className="absolute inset-0 h-full object-cover rounded-t-lg"
          />
        </div>
      )}
      <div className="mt-4">
        <h3 className="text-xl font-semibold text-primary-dark">{title}</h3>
        <div className="mt-2">{description}</div>
      </div>
    </div>
  );
}

export default Card;
