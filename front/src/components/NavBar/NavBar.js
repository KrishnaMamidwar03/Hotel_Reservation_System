// import React, { useState, useRef, useEffect } from "react";
// import { Link } from "react-router-dom";
// import { FaBars, FaTimes } from "react-icons/fa";

// function NavBar() {
//   const [isOpen, setIsOpen] = useState(false);
//   const menuRef = useRef(null);

//   const toggleMenu = () => setIsOpen(!isOpen);

//   const handleClickOutside = (event) => {
//     if (menuRef.current && !menuRef.current.contains(event.target)) {
//       setIsOpen(false);
//     }
//   };

//   useEffect(() => {
//     document.addEventListener("mousedown", handleClickOutside);
//     return () => document.removeEventListener("mousedown", handleClickOutside);
//   }, []);

//   return (
//     <nav className="bg-gray-800 text-white shadow-lg fixed w-full top-0 z-50 transition-transform duration-300 h-16">
//       <div className="container mx-auto flex justify-between items-center p-4">
//         <div className="navbar-logo text-3xl font-serif font-bold">
//           <Link
//             to="/"
//             className="hover:text-yellow-500 transition-colors duration-300"
//           >
//             YourPlace
//           </Link>
//         </div>
//         <div className="block lg:hidden">
//           <button onClick={toggleMenu} className="text-3xl">
//             {isOpen ? <FaTimes /> : <FaBars />}
//           </button>
//         </div>
//         <ul
//           ref={menuRef}
//           className={`lg:flex lg:space-x-8 lg:static lg:bg-transparent lg:p-0 fixed top-0 right-0 w-full lg:w-auto bg-gray-800 transition-transform duration-300 ${
//             isOpen ? "translate-x-0" : "translate-x-full"
//           } lg:translate-x-0`}
//         >
//           {[
//             "about-us",
//             "rooms",
//             "amenities",
//             "reviews",
//             "contact",
//             "login",
//             "signup",
//           ].map((section, index) => (
//             <li key={index} className="p-4 lg:p-0">
//               <Link
//                 to={`/${section}`}
//                 className="block lg:inline text-lg hover:text-yellow-500 transition-colors duration-300"
//                 onClick={toggleMenu}
//               >
//                 {section.charAt(0).toUpperCase() +
//                   section.slice(1).replace("-", " ")}
//               </Link>
//             </li>
//           ))}
//         </ul>
//       </div>
//     </nav>
//   );
// }

// export default NavBar;

import React, { useState, useRef, useEffect } from "react";
import { Link } from "react-router-dom";
import { FaBars, FaTimes } from "react-icons/fa";

function NavBar() {
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef(null);

  const toggleMenu = () => setIsOpen(!isOpen);

  const handleClickOutside = (event) => {
    if (menuRef.current && !menuRef.current.contains(event.target)) {
      setIsOpen(false);
    }
  };

  useEffect(() => {
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <nav className="bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 text-white shadow-lg fixed w-full top-0 z-50 transition-transform duration-300 h-16 flex items-center justify-between px-6">
      <div className="container mx-auto flex justify-between items-center p-2">
        <div className="navbar-logo text-3xl font-serif font-bold">
          <path d="M0 0h24v24H0z" fill="none" />
          <path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z" />
          <i class="bi bi-house-fill"></i>
          <Link
            to="/"
            className="hover:text-yellow-500 transition-colors duration-300"
          >
            YourPlace
          </Link>
        </div>
        <div className="block lg:hidden">
          <button onClick={toggleMenu} className="text-3xl">
            {isOpen ? <FaTimes /> : <FaBars />}
          </button>
        </div>
        <ul
          ref={menuRef}
          className={`lg:flex lg:space-x-8 lg:static lg:bg-transparent lg:p-0 fixed top-0 right-0 w-full lg:w-auto bg-gray-800 transition-transform duration-300 ${isOpen ? "translate-x-0" : "translate-x-full"
            } lg:translate-x-0`}
        >
          {["login", "Register", "About-Us"].map(
            (section, index) => (
              <li key={index} className="p-4 lg:p-0">
                <Link
                  to={`/${section}`}
                  className="block lg:inline text-lg hover:text-yellow-500 transition-colors duration-300"
                  onClick={toggleMenu}
                >
                  {section.charAt(0).toUpperCase() +
                    section.slice(1).replace("-", " ")}
                </Link>
              </li>
            )
          )}
        </ul>
      </div>
    </nav>
  );
}

export default NavBar;