// controllers/authController.js
import bcrypt from "bcrypt";
import validator from "validator";
import { generateToken } from "../config/jwt.js";
import { sendMail } from "../config/mailer.js";
import OTP from "../models/OTP.js";
import User from "../models/User.js";
import Log from "../models/Log.js";
import { checkSuspiciousActivity } from "../utils/alertUtils.js"; // 🔥 NEW IMPORT

// Helper function to get client info
const getClientInfo = (req) => ({
  ipAddress: req.ip || req.connection.remoteAddress || "Unknown",
  userAgent: req.headers["user-agent"] || "Unknown",
});

// ✅ Helper function to create logs + trigger alerts for suspicious levels
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

    // 🔥 Yahan se REAL-TIME ALERT trigger hoga (sirf warning / error / suspicious pe)
    if (["warning", "error", "suspicious"].includes(level)) {
      const userEmail = metadata?.userEmail || null;
      await checkSuspiciousActivity(log, userEmail);
    }
  } catch (error) {
    console.error("Log creation error:", error);
  }
};

// ✅ Signup - Step 1: Send Verification Email
export const signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const clientInfo = getClientInfo(req);

    if (!validator.isEmail(email)) {
      await createLog(
        "warning",
        `Signup attempt with invalid email: ${email}`,
        ["authentication", "signup"],
        clientInfo.ipAddress,
        clientInfo.userAgent,
        { userEmail: email }
      );
      return res.status(400).json({ message: "Invalid email format" });
    }

    if (!password || password.length < 6) {
      await createLog(
        "warning",
        `Signup attempt with weak password`,
        ["authentication", "signup"],
        clientInfo.ipAddress,
        clientInfo.userAgent,
        { userEmail: email }
      );
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      await createLog(
        "warning",
        `Signup attempt for existing email: ${email}`,
        ["authentication", "signup"],
        clientInfo.ipAddress,
        clientInfo.userAgent,
        { userEmail: email }
      );
      return res.status(400).json({ message: "Email already registered" });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.deleteMany({ email });

    const hashed = await bcrypt.hash(password, 10);
    await OTP.create({
      email,
      code,
      userData: { name, email, password: hashed },
    });

    // Log successful signup attempt
    await createLog(
      "info",
      `Signup initiated for ${email}`,
      ["authentication", "signup"],
      clientInfo.ipAddress,
      clientInfo.userAgent,
      { userEmail: email }
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verify Your Email - SEO Intrusion Detector",
      html: `<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2>Welcome, ${name}!</h2>
        <p>Your verification code is: <strong>${code}</strong></p>
        <p>This code will expire in 5 minutes.</p>
      </div>`,
      text: `Welcome ${name}! Your email verification code is: ${code}\n\nThis code will expire in 5 minutes.`,
    };

await sendMail({
  to: email,
  subject: "Login OTP - SEO Intrusion Detector",
  html: "<h2>Your OTP...</h2>",
});

    res.json({
      message: "Verification code sent to your email",
      email: email,
      requiresVerification: true,
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ message: "Server error during signup" });
  }
};

// ✅ Verify Email
export const verifyEmail = async (req, res) => {
  try {
    const { email, code } = req.body;
    const clientInfo = getClientInfo(req);

    if (!validator.isEmail(email)) {
      await createLog(
        "warning",
        `Email verification with invalid email format`,
        ["authentication"],
        clientInfo.ipAddress,
        clientInfo.userAgent,
        { userEmail: email }
      );
      return res.status(400).json({ message: "Invalid email format" });
    }

    if (!code || code.length !== 6) {
      await createLog(
        "warning",
        `Email verification failed - invalid OTP`,
        ["authentication"],
        clientInfo.ipAddress,
        clientInfo.userAgent,
        { userEmail: email }
      );
      return res.status(400).json({ message: "Invalid verification code" });
    }

    const otpRecord = await OTP.findOne({ email, code });
    if (!otpRecord) {
      await createLog(
        "warning",
        `Email verification failed - expired OTP for ${email}`,
        ["authentication"],
        clientInfo.ipAddress,
        clientInfo.userAgent,
        { userEmail: email }
      );
      return res
        .status(400)
        .json({ message: "Invalid or expired verification code" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      await OTP.deleteOne({ email, code });
      await createLog(
        "warning",
        `Email verification - user already exists: ${email}`,
        ["authentication"],
        clientInfo.ipAddress,
        clientInfo.userAgent,
        { userEmail: email }
      );
      return res.status(400).json({ message: "Email already registered" });
    }

    const user = await User.create({
      name: otpRecord.userData.name,
      email: otpRecord.userData.email,
      password: otpRecord.userData.password,
      emailVerified: true,
    });

    await OTP.deleteOne({ email, code });

    // Log successful verification and signup
    await createLog(
      "info",
      `User registered successfully: ${email}`,
      ["authentication", "signup"],
      clientInfo.ipAddress,
      clientInfo.userAgent,
      { userEmail: email }
    );

    const token = generateToken(user);
    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
      message: "Email verified successfully",
    });
  } catch (err) {
    console.error("Verify email error:", err);
    res.status(500).json({ message: "Server error during verification" });
  }
};

// ✅ Login with attempt tracking + REAL-TIME ALERTS on failure
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const clientInfo = getClientInfo(req);

    const user = await User.findOne({ email });
    if (!user) {
      await createLog(
        "warning",
        `Login failed - user not found: ${email}`,
        ["authentication", "login"],
        clientInfo.ipAddress,
        clientInfo.userAgent,
        { userEmail: email }
      );
      return res.status(401).json({
        message: "Invalid email or password. Please try again.",
        locked: false,
        attemptsRemaining: null,
      });
    }

    if (user.isAccountLocked && user.isAccountLocked()) {
      const lockTimeRemaining = Math.ceil(
        (user.lockUntil - Date.now()) / 60000
      );
      await createLog(
        "suspicious",
        `Login attempt on locked account: ${email}`,
        ["authentication", "login", "locked"],
        clientInfo.ipAddress,
        clientInfo.userAgent,
        { userEmail: email }
      );

      return res.status(423).json({
        message: `Account locked due to multiple failed login attempts. Please try again in ${lockTimeRemaining} minutes.`,
        locked: true,
        attemptsRemaining: 0,
        suggestReset: true,
      });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      await user.incLoginAttempts();
      const updatedUser = await User.findById(user._id);
      const attemptsRemaining = 3 - updatedUser.loginAttempts;

      await createLog(
        "warning",
        `Failed login attempt for ${email} (${updatedUser.loginAttempts} attempts)`,
        ["authentication", "login", "failed"],
        clientInfo.ipAddress,
        clientInfo.userAgent,
        { userEmail: email }
      );

      if (attemptsRemaining <= 0) {
        await createLog(
          "suspicious",
          `Account locked after failed login attempts: ${email}`,
          ["authentication", "login", "locked", "brute_force"],
          clientInfo.ipAddress,
          clientInfo.userAgent,
          { userEmail: email }
        );

        return res.status(401).json({
          message:
            "Too many failed login attempts. Your account has been locked for 15 minutes.",
          locked: true,
          attemptsRemaining: 0,
          suggestReset: true,
        });
      }

      return res.status(401).json({
        message: `Invalid password. ${attemptsRemaining} attempt(s) remaining.`,
        locked: false,
        attemptsRemaining: attemptsRemaining,
        suggestReset: attemptsRemaining === 1,
      });
    }

    if (user.loginAttempts > 0 || user.lockUntil) {
      await user.resetLoginAttempts();
    }

    // 🔹 send OTP on successful login
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.deleteMany({ email });
    await OTP.create({ email, code });

    await createLog(
      "info",
      `Login OTP sent to ${email}`,
      ["authentication", "login", "otp"],
      clientInfo.ipAddress,
      clientInfo.userAgent,
      { userEmail: email }
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Login OTP - SEO Intrusion Detector",
      html: `<div style="font-family: Arial, sans-serif;">
        <h2>Login Verification</h2>
        <p>Your one-time login code is: <strong>${code}</strong></p>
        <p>This code will expire in 5 minutes.</p>
      </div>`,
    };

await sendMail({
  to: email,
  subject: "Login OTP - SEO Intrusion Detector",
  html: "<h2>Your OTP...</h2>",
});;

    await createLog(
      "info",
      `User logged in successfully: ${email}`,
      ["authentication", "login", "success"],
      clientInfo.ipAddress,
      clientInfo.userAgent,
      { userEmail: email }
    );

    res.json({
      token: generateToken(user),
      user: { id: user._id, name: user.name, email: user.email },
      otpSent: true,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error during login" });
  }
};

// ✅ OTP verify for login / google
export const verifyLoginOtp = async (req, res) => {
  try {
    const { email, code } = req.body;
    const clientInfo = getClientInfo(req);

    if (!validator.isEmail(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    if (!code || code.length !== 6) {
      return res.status(400).json({ message: "Invalid OTP code" });
    }

    const otpRecord = await OTP.findOne({ email, code });
    if (!otpRecord) {
      await createLog(
        "warning",
        `Login OTP verification failed for ${email}`,
        ["authentication", "login", "otp"],
        clientInfo.ipAddress,
        clientInfo.userAgent,
        { userEmail: email }
      );
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    await OTP.deleteOne({ email, code });

    await createLog(
      "info",
      `Login OTP verified for ${email}`,
      ["authentication", "login", "otp_success"],
      clientInfo.ipAddress,
      clientInfo.userAgent,
      { userEmail: email }
    );

    return res.json({ message: "OTP verified successfully" });
  } catch (err) {
    console.error("Login OTP verify error:", err);
    res
      .status(500)
      .json({ message: "Server error during login OTP verification" });
  }
};

// ✅ Forgot Password
export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const clientInfo = getClientInfo(req);

    if (!validator.isEmail(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      await createLog(
        "warning",
        `Password reset requested for non-existent email: ${email}`,
        ["authentication", "password"],
        clientInfo.ipAddress,
        clientInfo.userAgent,
        { userEmail: email }
      );
      return res.status(404).json({ message: "No account found with this email" });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.deleteMany({ email });
    await OTP.create({ email, code });

    await createLog(
      "info",
      `Password reset requested for ${email}`,
      ["authentication", "password"],
      clientInfo.ipAddress,
      clientInfo.userAgent,
      { userEmail: email }
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset OTP - SEO Intrusion Detector",
      html: `<div style="font-family: Arial, sans-serif;"><h2>Password Reset</h2><p>Your OTP is: <strong>${code}</strong></p></div>`,
    };
await sendMail({
  to: email,
  subject: "Login OTP - SEO Intrusion Detector",
  html: "<h2>Your OTP...</h2>",
});
    res.json({ message: "OTP sent successfully", email });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ message: "Failed to send OTP" });
  }
};

// ✅ Reset Password
export const resetPassword = async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    const clientInfo = getClientInfo(req);

    if (!validator.isEmail(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    if (!code || code.length !== 6) {
      return res.status(400).json({ message: "Invalid OTP code" });
    }

    if (!newPassword || newPassword.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters" });
    }

    const otp = await OTP.findOne({ email, code });
    if (!otp) {
      await createLog(
        "warning",
        `Password reset failed - invalid OTP for ${email}`,
        ["authentication", "password"],
        clientInfo.ipAddress,
        clientInfo.userAgent,
        { userEmail: email }
      );
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    await User.findOneAndUpdate({ email }, { password: hashed });
    await OTP.deleteOne({ email, code });

    await createLog(
      "info",
      `Password reset successfully for ${email}`,
      ["authentication", "password"],
      clientInfo.ipAddress,
      clientInfo.userAgent,
      { userEmail: email }
    );

    res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ message: "Server error during password reset" });
  }
};

// ✅ Google Login + OTP SEND
export const googleLogin = async (req, res) => {
  try {
    const { email, name } = req.body;
    const clientInfo = getClientInfo(req);

    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({
        name,
        email,
        password: "",
        googleId: email,
        emailVerified: true,
      });

      await createLog(
        "info",
        `New user registered via Google: ${email}`,
        ["authentication", "google"],
        clientInfo.ipAddress,
        clientInfo.userAgent,
        { userEmail: email }
      );
    } else {
      await createLog(
        "info",
        `User logged in via Google: ${email}`,
        ["authentication", "google"],
        clientInfo.ipAddress,
        clientInfo.userAgent,
        { userEmail: email }
      );
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.deleteMany({ email });
    await OTP.create({ email, code });

    await createLog(
      "info",
      `Google login OTP sent to ${email}`,
      ["authentication", "google", "otp"],
      clientInfo.ipAddress,
      clientInfo.userAgent,
      { userEmail: email }
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Google Login OTP - SEO Intrusion Detector",
      html: `<div style="font-family: Arial, sans-serif;">
        <h2>Google Login Verification</h2>
        <p>Your one-time login code is: <strong>${code}</strong></p>
        <p>This code will expire in 5 minutes.</p>
      </div>`,
    };
await sendMail({
  to: email,
  subject: "Login OTP - SEO Intrusion Detector",
  html: "<h2>Your OTP...</h2>",
});

    const token = generateToken(user);
    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
      otpSent: true,
    });
  } catch (err) {
    console.error("Google login error:", err);
    res.status(500).json({ message: "Google login failed" });
  }
};

// ✅ Resend Verification Code
export const resendVerification = async (req, res) => {
  try {
    const { email } = req.body;
    const clientInfo = getClientInfo(req);

    if (!validator.isEmail(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    const existingOTP = await OTP.findOne({ email });
    if (!existingOTP) {
      return res
        .status(404)
        .json({ message: "No pending verification found for this email" });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.findOneAndUpdate({ email }, { code, createdAt: Date.now() });

    await createLog(
      "info",
      `Verification code resent for ${email}`,
      ["authentication"],
      clientInfo.ipAddress,
      clientInfo.userAgent,
      { userEmail: email }
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "New Verification Code - SEO Intrusion Detector",
      html: `<div style="font-family: Arial, sans-serif;"><h2>New Verification Code</h2><p>Your code is: <strong>${code}</strong></p></div>`,
    };
await sendMail({
  to: email,
  subject: "Login OTP - SEO Intrusion Detector",
  html: "<h2>Your OTP...</h2>",
});
    res.json({ message: "New verification code sent to your email" });
  } catch (err) {
    console.error("Resend verification error:", err);
    res.status(500).json({ message: "Failed to resend verification code" });
  }
};
