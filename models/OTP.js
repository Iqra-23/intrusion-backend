import mongoose from "mongoose";

const otpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  code: { type: String, required: true },
  userData: {
    name: String,
    email: String,
    password: String // This will be hashed
  },
  createdAt: { type: Date, default: Date.now, expires: 300 } // expires in 5 minutes
});

export default mongoose.model("OTP", otpSchema);