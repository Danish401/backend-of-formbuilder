// working version 14.09.24


// const express = require("express");
// const jwt = require("jsonwebtoken");
// const bcrypt = require("bcrypt");
// const User = require("../models/User");
// const router = express.Router();
// const passport = require("passport");
// require("dotenv").config();
// const GoogleStrategy = require("passport-google-oauth20").Strategy;

// const cookieParser = require("cookie-parser");
// const jwtSecret = process.env.JWT_SECRET;


// passport.use(
//   new GoogleStrategy(
//     {
//       clientID: process.env.GOOGLE_CLIENT_ID,
//       clientSecret: process.env.GOOGLE_CLIENT_SECRET,
//       callbackURL: `${process.env.BACKEND_URL}/auth/google/callback`,
//     },
//     async (accessToken, refreshToken, profile, done) => {
//       try {
//         // Check if user exists by email
//         const email = profile.emails[0].value;
//         let user = await User.findOne({ email });

//         if (user) {
//           return done(null, user); // User exists, proceed
//         }

//         // Create a new user if not found
//         user = new User({
//           fullName: profile.displayName,
//           email: email,
//           password: null, // No password for Google OAuth users
//         });

//         await user.save();
//         return done(null, user);
//       } catch (err) {
//         return done(err, false);
//       }
//     }
//   )
// );

// // Serialize and deserialize the user (optional)
// passport.serializeUser((user, done) => {
//   done(null, user.id);
// });

// passport.deserializeUser(async (id, done) => {
//   try {
//     const user = await User.findById(id);
//     done(null, user);
//   } catch (err) {
//     done(err, false);
//   }
// });

// // Redirect to Google for authentication
// router.get(
//   "/google",
//   passport.authenticate("google", { scope: ["profile", "email"] })
// );


// // Google OAuth callback
// router.get(
//   "/google/callback",
//   passport.authenticate("google", { session: false, failureRedirect: "/login" }),
//   (req, res) => {
//     const token = jwt.sign({ id: req.user._id }, jwtSecret, { expiresIn: "1h" });
//     res.cookie("jwt", token, { httpOnly: true });
//     res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
//   }
// );



// router.post("/signup", async (req, res) => {
//   const { name, email, password } = req.body;
//   try {
//     // Check if the email is already in use
//     let user = await User.findOne({ email });
//     if (user) return res.status(400).json({ message: "Email already in use" });

//     // Create a new user
//     user = new User({ name, email, password });
//     await user.save();

//     // Generate JWT token
//     const token = jwt.sign({ id: user._id }, jwtSecret, { expiresIn: "1h" });
//     res.status(201).json({ token });
//   } catch (err) {
//     res.status(500).json({ error: "Server error" });
//   }
// });

// // Login Route
// // Login Route
// router.post("/login", async (req, res) => {
//   const { email, password } = req.body;
//   try {
//     // Find user by email
//     const user = await User.findOne({ email });
//     if (!user) return res.status(404).json({ message: "User not found" });

//     // Compare passwords
//     const isMatch = await user.comparePassword(password);
//     if (!isMatch)
//       return res.status(400).json({ message: "Invalid credentials" });

//     // Generate JWT token
//     const token = jwt.sign({ id: user._id }, jwtSecret, { expiresIn: "1h" });
//     res.json({ token });
//   } catch (err) {
//     res.status(500).json({ error: "Server error" });
//   }
// });



// module.exports = router;


// // const express = require("express");
// // const jwt = require("jsonwebtoken");
// // const bcrypt = require("bcrypt");
// // const User = require("../models/User");
// // const router = express.Router();
// // const passport = require("passport");
// // require("dotenv").config();
// // const GoogleStrategy = require("passport-google-oauth20").Strategy;

// // const jwtSecret = process.env.JWT_SECRET;

// // // Google OAuth strategy
// // passport.use(
// //   new GoogleStrategy(
// //     {
// //       clientID: process.env.GOOGLE_CLIENT_ID,
// //       clientSecret: process.env.GOOGLE_CLIENT_SECRET,
// //       callbackURL: `${process.env.BACKEND_URL}/auth/google/callback`,
// //     },
// //     async (accessToken, refreshToken, profile, done) => {
// //       try {
// //         const email = profile.emails[0].value;
// //         let user = await User.findOne({ email });

// //         // If user exists, return the user
// //         if (user) {
// //           return done(null, user);
// //         }

// //         // Create a new user
// //         user = new User({
// //           fullName: profile.displayName,
// //           email: email,
// //           password: null, // No password for Google OAuth users
// //         });

// //         await user.save();
// //         return done(null, user);
// //       } catch (error) {
// //         return done(error, false);
// //       }
// //     }
// //   )
// // );

// // // Serialize and deserialize user
// // passport.serializeUser((user, done) => {
// //   done(null, user.id);
// // });

// // passport.deserializeUser(async (id, done) => {
// //   try {
// //     const user = await User.findById(id);
// //     done(null, user);
// //   } catch (error) {
// //     done(error, false);
// //   }
// // });

// // // Redirect to Google for authentication
// // router.get('/auth/google', (req, res, next) => {
// //   console.log("Google Auth route hit");
// //   passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
// // });

// // // Google Callback Route
// // router.get('/auth/google/callback', (req, res, next) => {
// //   passport.authenticate('google', (err, user, info) => {
// //     if (err) {
// //       return res.redirect('/error'); // Handle error appropriately
// //     }
// //     // Log in the user or handle the user session here
// //     req.logIn(user, (err) => {
// //       if (err) {
// //         return res.redirect('/error'); // Handle error appropriately
// //       }
// //       // Redirect to a success page or home
// //       return res.redirect('/'); 
// //     });
// //   })(req, res, next);
// // });

// // // Helper function to generate JWT
// // const generateToken = (userId) => {
// //   return jwt.sign({ id: userId }, jwtSecret, { expiresIn: "1h" });
// // };

// // // Sign up
// // router.post("/signup", async (req, res) => {
// //   const { name, email, password } = req.body;

// //   try {
// //     if (!name || !email || !password) {
// //       return res.status(400).json({ message: "All fields are required." });
// //     }

// //     // Check if email is already in use
// //     let existingUser = await User.findOne({ email });
// //     if (existingUser) {
// //       return res.status(400).json({ message: "Email already in use" });
// //     }

// //     // Hash password
// //     const hashedPassword = await bcrypt.hash(password, 10);

// //     // Create a new user
// //     const newUser = new User({ name, email, password: hashedPassword });
// //     await newUser.save();

// //     // Generate JWT token
// //     const token = generateToken(newUser._id);
// //     res.status(201).json({ token });
// //   } catch (error) {
// //     res.status(500).json({ error: "Server error" });
// //   }
// // });

// // // Login
// // router.post("/login", async (req, res) => {
// //   const { email, password } = req.body;

// //   try {
// //     if (!email || !password) {
// //       return res.status(400).json({ message: "All fields are required." });
// //     }

// //     const user = await User.findOne({ email });
// //     if (!user) {
// //       return res.status(404).json({ message: "User not found" });
// //     }

// //     const isMatch = await bcrypt.compare(password, user.password);
// //     if (!isMatch) {
// //       return res.status(400).json({ message: "Invalid credentials" });
// //     }

// //     const token = generateToken(user._id);
// //     res.json({ token });
// //   } catch (error) {
// //     res.status(500).json({ error: "Server error" });
// //   }
// // });

// // module.exports = router;

//working 
// const express = require("express");
// const jwt = require("jsonwebtoken");
// const bcrypt = require("bcrypt");
// const User = require("../models/User");
// const router = express.Router();
// const passport = require("passport");
// require("dotenv").config();
// const GoogleStrategy = require("passport-google-oauth20").Strategy;

// const cookieParser = require("cookie-parser");
// const jwtSecret = process.env.JWT_SECRET;


// // const verifyToken = (req, res, next) => {
// //   const token = req.cookies.token; // Assuming you store the token in a cookie
// //   if (!token) return res.status(403).json({ message: "Token is required" });

// //   jwt.verify(token, jwtSecret, (err, decoded) => {
// //     if (err) return res.status(401).json({ message: "Invalid token" });
// //     req.userId = decoded.id; // Set userId from the decoded token
// //     next();
// //   });
// // };

// passport.use(
//   new GoogleStrategy(
//     {
//       clientID: process.env.GOOGLE_CLIENT_ID,
//       clientSecret: process.env.GOOGLE_CLIENT_SECRET,
//       callbackURL:`${process.env.BACKEND_URL}/auth/google/callback`,
//       scope:["profile","email"]
//     },
//     async (accessToken, refreshToken, profile, done) => {
//       try {
//         let user = await User.findOne({googleId:profile.id});

//         if(!user){
//             user = new User({
//                 googleId:profile.id,
//                 displayName:profile.displayName,
//                 email:profile.emails[0].value,
//                 image:profile.photos[0].value
//             });

//             await user.save();
//         }

//         return done(null,user)
//     } catch (error) {
//         return done(error,null)
//     }
// }
//   )
// );

// // Serialize and deserialize the user (optional)
// passport.serializeUser((user, done) => {
//   done(null, user.id);
// });

// passport.deserializeUser(async (id, done) => {
//   try {
//     const user = await User.findById(id);
//     done(null, user);
//   } catch (err) {
//     done(err, false);
//   }
// });

// // Redirect to Google for authentication
// router.get(
//   "/google",
//   passport.authenticate("google", { scope: ["profile", "email"] })
// );


// // Google OAuth callback
// router.get(
//   "/google/callback",
//   passport.authenticate("google", { session: false, failureRedirect: "/login" }),
//   (req, res) => {
//     const token = jwt.sign({ id: req.user._id }, jwtSecret, { expiresIn: "1h" });
//     res.cookie("jwt", token, { httpOnly: true });
//     res.redirect(`${process.env.FRONTEND_URL}/`);
//   }
// );



// router.post("/signup", async (req, res) => {
//   const { name, email, password } = req.body;
//   try {
//     // Check if the email is already in use
//     let user = await User.findOne({ email });
//     if (user) return res.status(400).json({ message: "Email already in use" });

//     // Create a new user
//     user = new User({ name, email, password });
//     await user.save();

//     // Generate JWT token
//     const token = jwt.sign({ id: user._id }, jwtSecret, { expiresIn: "1h" });
//     res.cookie("token", token, { httpOnly: true, secure: process.env.NODE_ENV === "production" });
//     res.status(201).json({ token });
//   } catch (err) {
//     res.status(500).json({ error: "Server error" });
//   }
// });

// // Login Route
// // Login Route
// router.post("/login", async (req, res) => {
//   const { email, password } = req.body;
//   try {
//     const user = await User.findOne({ email });
//     if (!user) return res.status(404).json({ message: "User not found" });

//     const isMatch = await user.comparePassword(password);
//     if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

//     const token = jwt.sign({ id: user._id }, jwtSecret, { expiresIn: "1h" });
//     res.cookie("token", token, { httpOnly: true, secure: process.env.NODE_ENV === "production" });
//     // Send user data along with the token
//     res.json({ token, user });
//   } catch (err) {
//     res.status(500).json({ error: "Server error" });
//   }
// });

// // GET endpoint to fetch user data
// router.get("/user", async (req, res) => {
//   try {
//     const user = await User.findById(req.userId).select("name email");
//     if (!user) return res.status(404).json({ message: "User not found" });

//     res.json({ name: user.name, email: user.email });
//   } catch (err) {
//     res.status(500).json({ error: "Server error" });
//   }
// });


// // Logout API
// router.get("/logout", (req, res) => {
//   res.clearCookie("token"); // If the token is stored in a cookie
//   res.status(200).json({ message: "Logged out successfully" });
// });



// module.exports = router;






const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const User = require("../models/User");
const router = express.Router();
const passport = require("passport");
require("dotenv").config();
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const cookieParser = require("cookie-parser");
const jwtSecret = process.env.JWT_SECRET;


// const verifyToken = (req, res, next) => {
//   const token = req.cookies.token; // Assuming you store the token in a cookie
//   if (!token) return res.status(403).json({ message: "Token is required" });

//   jwt.verify(token, jwtSecret, (err, decoded) => {
//     if (err) return res.status(401).json({ message: "Invalid token" });
//     req.userId = decoded.id; // Set userId from the decoded token
//     next();
//   });
// };

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:`${process.env.BACKEND_URL}/auth/google/callback`,
      scope:["profile","email"]
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({googleId:profile.id});

        if(!user){
            user = new User({
                googleId:profile.id,
                displayName:profile.displayName,
                email:profile.emails[0].value,
                image:profile.photos[0].value
            });

            await user.save();
        }

        return done(null,user)
    } catch (error) {
        return done(error,null)
    }
}
  )
);

// Serialize and deserialize the user (optional)
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, false);
  }
});

// Redirect to Google for authentication
router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);


// Google OAuth callback
router.get(
  "/google/callback",
  passport.authenticate("google", { session: false, failureRedirect: "/login" }),
  (req, res) => {
    const token = jwt.sign({ id: req.user._id }, jwtSecret, { expiresIn: "1h" });
    res.cookie("jwt", token, { httpOnly: true });
    res.redirect(`${process.env.FRONTEND_URL}/`);
  }
);



router.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    // Check if the email is already in use
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: "Email already in use" });

    // Create a new user
    user = new User({ name, email, password });
    await user.save();

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, jwtSecret, { expiresIn: "1h" });
    res.cookie("token", token, { httpOnly: true, secure: process.env.NODE_ENV === "production" });
    res.status(201).json({ token });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Login Route
// Login Route
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, jwtSecret, { expiresIn: "1h" });
    res.cookie("token", token, { httpOnly: true, secure: process.env.NODE_ENV === "production" });
    // Send user data along with the token
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// GET endpoint to fetch user data
router.get("/user", async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("name email");
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ name: user.name, email: user.email });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});


// Logout API
router.get("/logout", (req, res) => {
  res.clearCookie("token"); // If the token is stored in a cookie
  res.status(200).json({ message: "Logged out successfully" });
});



module.exports = router;
