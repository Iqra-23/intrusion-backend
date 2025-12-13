import nodemailer from "nodemailer";
import dotenv from "dotenv";
dotenv.config();

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS, // Gmail App Password
  },
});

export const sendMail = async ({ to, subject, html }) => {
  if (!to) throw new Error("No recipient email");

  await transporter.sendMail({
    from: `"SEO Intrusion Detector" <${process.env.EMAIL_USER}>`,
    to,
    subject,
    html,
  });

  console.log("📧 Email sent to:", to);
};
