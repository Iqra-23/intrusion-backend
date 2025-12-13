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
router.post("/verify-login-otp", verifyLoginOtp);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);
router.post("/google-login", googleLogin);
router.post("/resend-verification", resendVerification);

export default router;
