// config/mailer.js
import { Resend } from "resend";

export const sendMail = async ({ to, subject, html }) => {
  if (!process.env.RESEND_API_KEY) {
    console.error("❌ RESEND_API_KEY missing");
    return;
  }

  const resend = new Resend(process.env.RESEND_API_KEY);

  try {
    await resend.emails.send({
      from: "SEO Intrusion <onboarding@resend.dev>",
      to,
      subject,
      html,
    });
    console.log(`📧 Email sent to ${to}`);
  } catch (error) {
    console.error("❌ Email send failed:", error);
  }
};
