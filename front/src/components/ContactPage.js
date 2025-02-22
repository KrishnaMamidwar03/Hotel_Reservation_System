import React from 'react';

function ContactPage() {
  return (
    <div className="container mx-auto px-4 py-16">
      <h2 className="text-4xl font-serif font-bold text-primary-dark mb-6 text-center">
        Contact Us
      </h2>
      <form className="space-y-4 max-w-2xl mx-auto">
        <div>
          <label htmlFor="name" className="block text-lg text-gray-700">Name:</label>
          <input
            type="text"
            id="name"
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-dark"
          />
        </div>
        <div>
          <label htmlFor="email" className="block text-lg text-gray-700">Email:</label>
          <input
            type="email"
            id="email"
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-dark"
          />
        </div>
        <div>
          <label htmlFor="message" className="block text-lg text-gray-700">Message:</label>
          <textarea
            id="message"
            rows="4"
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-dark"
          ></textarea>
        </div>
        <button
          type="submit"
          className="px-4 py-2 bg-primary-dark text-white font-bold rounded-md hover:bg-primary-dark-dark"
        >
          Send
        </button>
      </form>
    </div>
  );
}

export default ContactPage;
