// import nodemailer from "nodemailer";
// import dotenv from "dotenv";
// dotenv.config();

// export const transporter = nodemailer.createTransport({
//   host: process.env.EMAIL_HOST,   // mail.gmx.com
//   port: process.env.SMTP_PORT,    // 587
//   secure: true,                  // false for port 587 (STARTTLS)
//   auth: {
//     user: process.env.EMAIL_USER, // SEOINTRUSION-DETECTOR@gmx.com
//     pass: process.env.EMAIL_PASS  // mohib@3764
//   },
//   tls: {
//     rejectUnauthorized: false     // optional: allows self-signed certificates
//   }
// });

// // Test email connection on startup
// transporter.verify((error, success) => {
//   if (error) {
//     console.error("❌ Email configuration error:", error);
//   } else {
//     console.log("✅ Email server is ready to send messages");
//   }
// });


import nodemailer from "nodemailer";
import { google } from "googleapis";
import dotenv from "dotenv";

dotenv.config();

const OAuth2 = google.auth.OAuth2;

const oauth2Client = new OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  "https://developers.google.com/oauthplayground"
);

oauth2Client.setCredentials({
  refresh_token: process.env.REFRESH_TOKEN,
});

export const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    type: "OAuth2",
    user: process.env.EMAIL_USER,
    clientId: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    refreshToken: process.env.REFRESH_TOKEN,
    accessToken: async () => {
      const accessToken = await oauth2Client.getAccessToken();
      return accessToken?.token;
    },
  },
});

// ✅ Verify transporter
transporter.verify((error) => {
  if (error) {
    console.error("❌ Gmail OAuth transporter error:", error);
  } else {
    console.log("✅ Gmail OAuth transporter is ready");
  }
});
