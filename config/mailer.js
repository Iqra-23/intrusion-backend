import nodemailer from "nodemailer";

// config/mailer.js
import { Resend } from "resend";
import dotenv from "dotenv";
dotenv.config();


export const sendMail = async ({ to, subject, html, text }) => {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    throw new Error("EMAIL_USER or EMAIL_PASS missing");
  }

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  return transporter.sendMail({
    from: `"SEO Intrusion Detector" <${process.env.EMAIL_USER}>`,
    to,
    subject,
    html,
    text,
  });
};
