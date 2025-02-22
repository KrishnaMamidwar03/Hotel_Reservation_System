import React from "react";

function Reviews() {
  return (
    <div className="container mx-auto px-4 py-16">
      <h2 className="text-4xl font-serif font-bold text-yellow-500 mb-6 text-center">
        Guest Reviews
      </h2>
      <div className="space-y-8 max-w-2xl mx-auto">
        <blockquote className="text-lg text-gray-200 border-l-4 border-yellow-500 pl-4">
          <p>"Amazing stay! The service was exceptional, and the rooms were beautiful."</p>
          <footer>- John Doe</footer>
        </blockquote>
        <blockquote className="text-lg text-gray-200 border-l-4 border-yellow-500 pl-4">
          <p>"A luxurious experience that I will never forget. Highly recommended!"</p>
          <footer>- Jane Smith</footer>
        </blockquote>
      </div>
    </div>
  );
}

export default Reviews;
