// middleware/auth.js
const jwt = require("jsonwebtoken");
require("dotenv").config();

const cors = require('cors');



const auth = (req, res, next) => {
    // Access token from cookies or headers
    const token = req.cookies.token || req.header("Authorization")?.replace("Bearer ", "");
    
    if (!token) {
      return res.status(401).json({ message: "No token, authorization denied" });
    }
    
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded.id; // Store user ID in request for later use
      next();
    } catch (err) {
      res.status(401).json({ message: "Token is not valid" });
    }
  };
  

module.exports = auth;
