import dotenv from 'dotenv';
import nodemailer from 'nodemailer';

dotenv.config();

const {
  EMAIL_FROM_NAME = 'iRehab',
  EMAIL_FROM_ADDR,
  EMAIL_SMTP_USER,
  EMAIL_SMTP_PASS,
  EMAIL_SMTP_HOST = 'smtp.gmail.com',
  EMAIL_SMTP_PORT = '465',
  EMAIL_SMTP_SECURE = 'true',
} = process.env;

console.log('[Email] SMTP config:', {
  host: EMAIL_SMTP_HOST,
  port: EMAIL_SMTP_PORT,
  secure: EMAIL_SMTP_SECURE,
  user: EMAIL_SMTP_USER,
});

const transporter = nodemailer.createTransport({
  host: EMAIL_SMTP_HOST,                       
  port: Number(EMAIL_SMTP_PORT || 465),
  secure: EMAIL_SMTP_SECURE === 'true',       
  auth: {
    user: EMAIL_SMTP_USER,
    pass: EMAIL_SMTP_PASS,
  },
});

export async function sendResetOtpEmail(toEmail, code) {
  const mailOptions = {
    from: `"${EMAIL_FROM_NAME}" <${EMAIL_FROM_ADDR}>`,
    to: toEmail,
    subject: 'i-復健｜密碼重設驗證碼',
    text: `您的驗證碼為：${code}，10 分鐘內有效。`,
    html: `
      <p>您好，</p>
      <p>您正在使用 i-復健 的「忘記密碼」功能。</p>
      <p><b>驗證碼：${code}</b></p>
      <p>此驗證碼在 10 分鐘內有效，若非您本人操作請忽略本信件。</p>
    `,
  };

  await transporter.sendMail(mailOptions);
}