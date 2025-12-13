// config/mailer.js
import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY);

export const sendMail = async ({ to, subject, html }) => {
  try {
    const data = await resend.emails.send({
      from: "SEO Intrusion <onboarding@resend.dev>",
      to,
      subject,
      html,
    });

    console.log("✅ Email sent:", data);
    return data;
  } catch (error) {
    console.error("❌ Email send failed:", error);
    throw error;
  }
};
