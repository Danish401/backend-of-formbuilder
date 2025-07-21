// working perfect
const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const bodyParser = require("body-parser");
const cors = require("cors");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");
// const authRoutes = require("./routes/auth");
const cloudinary = require("cloudinary").v2; // Import Cloudinary
require("dotenv").config();
const nodemailer = require("nodemailer");
const path = require("path");
const app = express();
const PORT = process.env.PORT || 5000;
const session = require("express-session");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const OAuth2Strategy = require("passport-google-oauth2").Strategy;
const User = require("./models/User");
const crypto = require("crypto"); // To generate a random OTP
// Middleware
const jwtSecret = process.env.JWT_SECRET;

app.use(bodyParser.json());
app.use(
  cors({
    origin: "http://localhost:5173",
    methods: "GET,POST,PUT,DELETE",
    credentials: true,
  })
);
app.use(express.json());
// Configure Cloudinary
cloudinary.config({
  cloud_name: "dfbtey2ld",
  api_key: "523974768834469",
  api_secret: "E0zGVyzWVacljB3cn8VNloyRNQk",
});

let users = {
  "audreanne.wunsch48@ethereal.email": { password: "EXW5anVZCbcHJbD76r" },
};
let otps = {};

const sendMail = async (email, otp) => {
  let transporter = nodemailer.createTransport({
    host: "smtp.ethereal.email",
    port: 587,
    auth: {
      user: "audreanne.wunsch48@ethereal.email", // replace with your ethereal email
      pass: "EXW5anVZCbcHJbD76r", // replace with your ethereal password
    },
  });

  await transporter.sendMail({
    from: "alid13381@gmail.com",
    to: email,
    subject: "Your OTP for Password Reset",
    text: `Your OTP is: ${otp}`,
    html: `<b>Your OTP is: ${otp}</b>`,
  });
};

app.post("/api/forgotpassword", async (req, res) => {
  const { email } = req.body;

  if (!users[email]) {
    return res.status(404).json({ message: "User not found" });
  }

  const otp = crypto.randomInt(100000, 999999).toString();
  otps[email] = otp;

  await sendMail(email, otp);
  res.status(200).json({ message: "OTP sent to your email" });
});

app.post("/api/resetpassword", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  // Check if OTP is valid
  if (otps[email] && otps[email] === otp) {
    try {
      // Find the user by email
      let user = await User.findOne({ email });

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Update the password field with the new password (it will be hashed in the pre-save hook)
      user.password = newPassword;

      // Save the updated user
      await user.save();

      // Delete the OTP as it's no longer needed
      delete otps[email];

      console.log(`Updated password for ${email}: ${user.password}`); // Debugging line
      return res.status(200).json({ message: "Password updated successfully" });
    } catch (err) {
      return res.status(500).json({ message: "Error updating password" });
    }
  } else {
    return res.status(400).json({ message: "Invalid OTP" });
  }
});

// Sample user for demo purposes

// Forgot Password Route

app.post("/api/resetpassword", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (otps[email] && otps[email] === otp) {
    // Hash the new password before saving it
    try {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);

      // Update the user's password in MongoDB
      users[email].password = hashedPassword;

      // Delete the OTP as it's no longer needed
      delete otps[email];

      console.log(`Updated password for ${email}: ${users[email].password}`); // Debugging line
      return res.status(200).json({ message: "Password updated successfully" });
    } catch (err) {
      return res.status(500).json({ message: "Error updating password" });
    }
  } else {
    return res.status(400).json({ message: "Invalid OTP" });
  }
});

app.use(
  session({
    secret: "acn546dnwjn", // Use a strong secret
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Set to true if using HTTPS
  })
);
app.use(passport.initialize());
app.use(passport.session());
const clientid =
  "751697629319-kgjmketp0t3dj8hoaqe7vi18ef6fs73a.apps.googleusercontent.com";
const clientsecret = "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";

passport.use(
  new OAuth2Strategy(
    {
      clientID: clientid,
      clientSecret: clientsecret,
      callbackURL: "/auth/google/callback",
      scope: ["profile", "email"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });

        if (!user) {
          user = new User({
            googleId: profile.id,
            displayName: profile.displayName,
            email: profile.emails[0].value,
            image: profile.photos[0].value,
          });

          await user.save();
        }

        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// initial google ouath login
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    successRedirect: "http://localhost:3000",
    failureRedirect: "http://localhost:3000/login",
  })
);

app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: "Email already in use" });

    user = new User({ name, email, password });
    await user.save();

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, jwtSecret, { expiresIn: "1h" });

    // Store token in cookie (HTTP-only cookie)
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Use secure cookies in production
      sameSite: "strict", // Prevent CSRF
    });

    res.status(201).json({
      message: "Signup successful",
      token, // Optionally, send token back for frontend storage if needed
      user: { id: user._id, name: user.name, email: user.email }, // Send user data
    });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Login Route
// Login Route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });
    console.log(user);
    const isMatch = await user.comparePassword(password); // Assuming you have a password comparison method
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, jwtSecret, { expiresIn: "1h" });
    console.log(token);

    // Store token in cookie (HTTP-only cookie)
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Use secure cookies in production
      sameSite: "strict", // Prevent CSRF
    });
    console.log(res);
    // Send the user data to the frontend
    res.json({
      message: "Login successful",
      token, // Send token
      user: { id: user._id, name: user.name, email: user.email }, // Send user data
    });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// app.get('/login/success', (req, res) => {
//   console.log(req.user); // Check the user data
//   if (req.isAuthenticated()) {
//     res.status(200).json({
//       user: req.user,
//       message: 'Login successful',
//     });
//   } else {
//     res.status(401).json({ message: 'Not authenticated' });
//   }
// });

app.get("/login/success", (req, res) => {
  console.log(req.cookies); // Log cookies to debug
  console.log(req.user); // Check the user data
  if (req.isAuthenticated()) {
    res.status(200).json({
      user: req.user,
      message: "Login successful",
    });
  } else {
    res.status(401).json({ message: "Not authenticated" });
  }
});

app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    req.session.destroy((err) => {
      if (err) {
        return next(err);
      }
      // Instead of redirecting, send a success message
      res.status(200).json({ message: "Logged out successfully" });
    });
  });
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, "uploads/pdfs")); // Save PDFs here
  },
  filename: (req, file, cb) => {
    cb(null, ` ${Date.now()}-${file.originalname}`); // Save with a unique name
  },
});
const upload = multer({ storage });

// Connect to MongoDB

mongoose
  .connect("mongodb+srv://alid13381:danish29@cluster0.ucjqbgd.mongodb.net/", {
    // useNewUrlParser: true,
    // useUnifiedTopology: true, // You can remove this
  })
  .then(() => {
    console.log("MongoDB connected");
  })
  .catch((error) => {
    console.error("MongoDB connection error:", error);
  });

// Define the form schema
const formSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  info: { type: String, required: false },
  fields: { type: Array, required: true },
  imageUrl: { type: String, required: false }, // Add imageUrl field
  path: { type: String, required: false }, // Add path field (assuming you want to include it)
  layout: { type: Array, required: false },
});

const Form = mongoose.model("Form", formSchema);

app.post("/api/forms", upload.single("file"), async (req, res) => {
  // Changed "image" to "file"
  try {
    const formData = req.body;
    let fileUrl = null;

    // Upload file to Cloudinary if provided
    if (req.file) {
      const uploadOptions = {
        resource_type: "auto", // Automatically determines the type (image, video, etc.)
      };

      // Upload the file to Cloudinary
      const result = await cloudinary.uploader.upload_stream(uploadOptions);
      req.file.stream.pipe(result);
      fileUrl = result.secure_url; // Get the secure URL of the uploaded file
    }

    const newForm = new Form({
      id: formData.id || uuidv4(),
      name: formData.name,
      info: formData.info,
      fields: formData.fields,
      fileUrl: fileUrl || "", // Save the file URL
      path: formData.path || "", // Ensure path is included if needed
    });

    await newForm.save();
    return res
      .status(201)
      .json({ message: "Form saved successfully!", newForm });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/forms", async (req, res) => {
  try {
    const forms = await Form.find();
    return res.status(200).json(forms);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Get a form by ID
app.get("/api/forms/:id", async (req, res) => {
  try {
    const form = await Form.findOne({ id: req.params.id });
    if (!form) {
      return res.status(404).json({ message: "Form not found" });
    }
    return res.status(200).json(form);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Update a form by ID
app.put("/api/forms/:id", async (req, res) => {
  try {
    const { name, info, fields } = req.body;

    const updatedForm = await Form.findOneAndUpdate(
      { id: req.params.id },
      { name, info, fields },
      { new: true, runValidators: true }
    );

    if (!updatedForm) {
      return res.status(404).json({ message: "Form not found" });
    }

    return res
      .status(200)
      .json({ message: "Form updated successfully!", updatedForm });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Delete a form by ID
app.delete("/api/forms/:id", async (req, res) => {
  try {
    const deletedForm = await Form.findOneAndDelete({ id: req.params.id });

    if (!deletedForm) {
      return res.status(404).json({ message: "Form not found" });
    }

    return res.status(200).json({ message: "Form deleted successfully!" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/forms/upload", upload.single("files"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  const fileUrl = `http://localhost:${PORT}/uploads/pdfs/${req.file.filename}`;
  res.json({ url: fileUrl });
});

// Serve the uploaded files (optional)
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Other routes remain unchanged...

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
