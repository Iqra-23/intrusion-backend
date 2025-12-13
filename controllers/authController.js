// controllers/authController.js
import bcrypt from "bcrypt";
import validator from "validator";
import { generateToken } from "../config/jwt.js";
import { sendMail } from "../config/mailer.js";
import OTP from "../models/OTP.js";
import User from "../models/User.js";
import Log from "../models/Log.js";
import { checkSuspiciousActivity } from "../utils/alertUtils.js";

/* ---------------- CLIENT INFO ---------------- */
const getClientInfo = (req) => ({
  ipAddress: req.ip || req.connection?.remoteAddress || "Unknown",
  userAgent: req.headers["user-agent"] || "Unknown",
});

/* ---------------- SAFE LOG CREATOR ---------------- */
const createLog = async (
  level,
  message,
  keyword = [],
  ipAddress,
  userAgent,
  metadata = {}
) => {
  try {
    const log = await Log.create({
      level,
      message,
      keyword,
      ipAddress,
      userAgent,
      metadata,
    });

    // 🔥 NON-BLOCKING alert
    if (["warning", "error", "suspicious"].includes(level)) {
      const userEmail = metadata?.userEmail || null;
      checkSuspiciousActivity(log, userEmail).catch((err) =>
        console.error("Alert error:", err.message)
      );
    }
  } catch (err) {
    console.error("Log creation error:", err.message);
  }
};

/* ===================== SIGNUP ===================== */
export const signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const client = getClientInfo(req);

    if (!validator.isEmail(email))
      return res.status(400).json({ message: "Invalid email format" });

    if (!password || password.length < 6)
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters" });

    const exists = await User.findOne({ email });
    if (exists)
      return res.status(400).json({ message: "Email already registered" });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.deleteMany({ email });

    const hashed = await bcrypt.hash(password, 10);
    await OTP.create({
      email,
      code,
      userData: { name, email, password: hashed },
    });

    createLog(
      "info",
      `Signup initiated for ${email}`,
      ["authentication", "signup"],
      client.ipAddress,
      client.userAgent,
      { userEmail: email }
    );

    // 🔥 NON-BLOCKING EMAIL
    sendMail({
      to: email,
      subject: "Verify Your Email - SEO Intrusion Detector",
      html: `<h2>Your verification code is: ${code}</h2>`,
    }).catch((e) => console.error("Email error:", e.message));

    res.json({
      message: "Verification code sent",
      requiresVerification: true,
      email,
    });
  } catch (err) {
    console.error("Signup error:", err.message);
    res.status(500).json({ message: "Server error during signup" });
  }
};

/* ===================== VERIFY EMAIL ===================== */
export const verifyEmail = async (req, res) => {
  try {
    const { email, code } = req.body;

    const otp = await OTP.findOne({ email, code });
    if (!otp)
      return res
        .status(400)
        .json({ message: "Invalid or expired verification code" });

    const user = await User.create({
      name: otp.userData.name,
      email,
      password: otp.userData.password,
      emailVerified: true,
    });

    await OTP.deleteOne({ email, code });

    res.json({
      token: generateToken(user),
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error("Verify error:", err.message);
    res.status(500).json({ message: "Verification failed" });
  }
};

/* ===================== LOGIN ===================== */
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const client = getClientInfo(req);

    const user = await User.findOne({ email });
    if (!user)
      return res
        .status(401)
        .json({ message: "Invalid email or password" });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res
        .status(401)
        .json({ message: "Invalid email or password" });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.deleteMany({ email });
    await OTP.create({ email, code });

    // 🔥 SEND RESPONSE FIRST (CRITICAL FIX)
    res.json({
      token: generateToken(user),
      user: { id: user._id, name: user.name, email: user.email },
      otpSent: true,
    });

    // 🔥 BACKGROUND TASKS
    createLog(
      "info",
      `Login OTP sent to ${email}`,
      ["authentication", "login"],
      client.ipAddress,
      client.userAgent,
      { userEmail: email }
    );

    sendMail({
      to: email,
      subject: "Login OTP - SEO Intrusion Detector",
      html: `<h2>Your OTP is: ${code}</h2>`,
    }).catch((e) => console.error("Email error:", e.message));
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ message: "Server error during login" });
  }
};

/* ===================== VERIFY LOGIN OTP ===================== */
export const verifyLoginOtp = async (req, res) => {
  try {
    const { email, code } = req.body;

    const otp = await OTP.findOne({ email, code });
    if (!otp)
      return res.status(400).json({ message: "Invalid or expired OTP" });

    await OTP.deleteOne({ email, code });
    res.json({ message: "OTP verified successfully" });
  } catch (err) {
    res.status(500).json({ message: "OTP verification failed" });
  }
};

/* ===================== FORGOT PASSWORD ===================== */
export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ message: "User not found" });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.deleteMany({ email });
    await OTP.create({ email, code });

    sendMail({
      to: email,
      subject: "Password Reset OTP",
      html: `<h2>Your OTP is: ${code}</h2>`,
    }).catch(() => {});

    res.json({ message: "OTP sent successfully" });
  } catch (err) {
    res.status(500).json({ message: "Failed to send OTP" });
  }
};

/* ===================== RESET PASSWORD ===================== */
export const resetPassword = async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    const otp = await OTP.findOne({ email, code });
    if (!otp)
      return res.status(400).json({ message: "Invalid or expired OTP" });

    const hashed = await bcrypt.hash(newPassword, 10);
    await User.updateOne({ email }, { password: hashed });
    await OTP.deleteOne({ email, code });

    res.json({ message: "Password reset successful" });
  } catch (err) {
    res.status(500).json({ message: "Password reset failed" });
  }
};

/* ===================== GOOGLE LOGIN ===================== */
export const googleLogin = async (req, res) => {
  try {
    const { email, name } = req.body;

    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({
        name,
        email,
        password: "",
        googleId: email,
        emailVerified: true,
      });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.deleteMany({ email });
    await OTP.create({ email, code });

    res.json({
      token: generateToken(user),
      user: { id: user._id, name: user.name, email: user.email },
      otpSent: true,
    });

    sendMail({
      to: email,
      subject: "Google Login OTP",
      html: `<h2>Your OTP is: ${code}</h2>`,
    }).catch(() => {});
  } catch (err) {
    res.status(500).json({ message: "Google login failed" });
  }
};
