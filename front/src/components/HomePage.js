// import React from "react";
// import { useSpring, animated } from "@react-spring/web";

// function HomePage() {
//   const fadeInProps = useSpring({
//     opacity: 1,
//     from: { opacity: 0 },
//     config: { duration: 1000 },
//   });

//   return (
//     <div>
//       <animated.section
//         id="home"
//         style={fadeInProps}
//         className="flex flex-col items-center justify-center h-screen text-center px-4"
//       >
//         <h1 className="text-5xl font-bold text-yellow-500 mb-6">
//           Welcome To Hotel world
//         </h1>
//         <p className="text-lg text-gray-200 mb-8">
//           Experience and Enjoy in best hotels worldwide.
//         </p>
//       </animated.section>
//     </div>
//   );
// }

// export default HomePage;

import React from "react";
import { useSpring, animated } from "@react-spring/web";
import "./HomePage.css";

function HomePage() {
  const fadeInProps = useSpring({
    opacity: 1,
    from: { opacity: 0 },
    config: { duration: 1000 },
  });

  return (
    <div id="content">

    <div>
      {/* <animated.section
        id="home"
        style={fadeInProps}
        className="flex flex-col items-center justify-center h-screen text-center px-4"
      > */}
        {/* <h1 className="text-center custom-purple font-weight-bold mb-6" >
          Welcome to YourPlace
        </h1>
        <p className="text-lg text-white-200 mb-8">
          Experience luxury and comfort in the best hotels.
        </p> */}
      {/* </animated.section> */}
    </div>
    </div>
  );
}

export default HomePage;