import express from "express";
import {
  signup,
  verifyEmail,
  login,
  verifyLoginOtp,
  forgotPassword,
  resetPassword,
  googleLogin,
  resendVerification,
} from "../controllers/authController.js";

const router = express.Router();

// Signup
router.post("/signup", signup);
router.post("/verify-email", verifyEmail);

// Login
router.post("/login", login);
router.post("/login/verify-otp", verifyLoginOtp); // 🔥 THIS WAS MISSING / WRONG

// Password
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);

// Google
router.post("/google-login", googleLogin);

// Resend
router.post("/resend-verification", resendVerification);

export default router;
