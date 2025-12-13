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


import { google } from "googleapis";
import dotenv from "dotenv";

dotenv.config();

const oauth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  "https://developers.google.com/oauthplayground"
);

oauth2Client.setCredentials({
  refresh_token: process.env.REFRESH_TOKEN,
});

const gmail = google.gmail({
  version: "v1",
  auth: oauth2Client,
});

/**
 * Send email using Gmail API (Railway-safe)
 */
export const sendMail = async ({ to, subject, html }) => {
  const message = `
From: SEO Intrusion Detector <${process.env.EMAIL_USER}>
To: ${to}
Subject: ${subject}
Content-Type: text/html; charset="UTF-8"

${html}
  `;

  const encodedMessage = Buffer.from(message)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  await gmail.users.messages.send({
    userId: "me",
    requestBody: {
      raw: encodedMessage,
    },
  });
};
