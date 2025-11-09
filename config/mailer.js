import nodemailer from "nodemailer";
import dotenv from "dotenv";
dotenv.config();

export const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,   // mail.gmx.com
  port: process.env.SMTP_PORT,    // 587
  secure: false,                  // false for port 587 (STARTTLS)
  auth: {
    user: process.env.EMAIL_USER, // SEOINTRUSION-DETECTOR@gmx.com
    pass: process.env.EMAIL_PASS  // mohib@3764
  },
  tls: {
    rejectUnauthorized: false     // optional: allows self-signed certificates
  }
});

// Test email connection on startup
transporter.verify((error, success) => {
  if (error) {
    console.error("❌ Email configuration error:", error);
  } else {
    console.log("✅ Email server is ready to send messages");
  }
});
