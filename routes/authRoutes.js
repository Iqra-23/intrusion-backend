// routes/authRoutes.js
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

router.post("/signup", signup);
router.post("/verify-email", verifyEmail);
router.post("/login", login);
router.post("/login/verify-otp", verifyLoginOtp);
router.post("/forgot", forgotPassword);
router.post("/reset", resetPassword);
router.post("/google", googleLogin);
router.post("/resend-verification", resendVerification);

export default router;
