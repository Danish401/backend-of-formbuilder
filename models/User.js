// const mongoose = require("mongoose");
// const bcrypt = require("bcrypt");

// const userSchema = new mongoose.Schema({
//   name: { type: String },
//   email: { type: String, unique: true, required: true },
//   password: { type: String },
//   image:{String},
//   googleId: { type: String },
//   displayName:{String},
//   otp: { type: String },
//   otpExpiry: { type: Date },

// });

// // Hash password before saving to database
// userSchema.pre("save", async function (next) {
//   if (!this.isModified("password")) return next();
//   try {
//     const salt = await bcrypt.genSalt(10);
//     this.password = await bcrypt.hash(this.password, salt);
//     next();
//   } catch (err) {
//     next(err);
//   }
// });


// userSchema.methods.comparePassword = async function (password) {
//   try {
//     return await bcrypt.compare(password, this.password); // bcrypt compares raw and hashed password
//   } catch (err) {
//     throw new Error("Password comparison error");
//   }
// };

// module.exports = mongoose.model("User", userSchema);


// models/User.js
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
  name: { type: String },
  email: { type: String, unique: true, required: true },
  password: { type: String },
  image: { type: String },
  googleId: { type: String },
  displayName: { type: String },
  otp: { type: String },
  otpExpiry: { type: Date },
});

// Hash password before saving to database
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function (password) {
  try {
    return await bcrypt.compare(password, this.password); // bcrypt compares raw and hashed password
  } catch (err) {
    throw new Error("Password comparison error");
  }
};

module.exports = mongoose.model("User", userSchema);
