// config/mailer.js
import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS, // Gmail App Password
  },
});

export const sendMail = async ({ to, subject, html }) => {
  try {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      console.error("❌ EMAIL_USER or EMAIL_PASS missing");
      return;
    }

    // Ensure 'to' is a simple email address
    const recipient = to.includes('<') ? to.match(/<([^>]+)>/)[1] : to;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: recipient,
      subject,
      html,
    });

    console.log(`📧 Email sent to ${recipient}`);
  } catch (error) {
    console.error(`❌ Email send failed to ${to}:`, error);
  }
};
