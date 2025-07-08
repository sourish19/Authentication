import nodemailer from 'nodemailer';
import Mailgen from 'mailgen';

const mailGenerator = new Mailgen({
  theme: 'default',
  product: {
    name: 'FreeAPI',
    link: 'https://freeapi.app',
    logo: 'https://mailgen.js/img/logo.png',
    logoHeight: '30px',
    copyright: `© ${new Date().getFullYear()} FreeAPI. All rights reserved.`,
  },
});

const transporter = nodemailer.createTransport({
  host: process.env.MAILTRAP_HOST,
  port: parseInt(process.env.MAILTRAP_PORT, 10),
  secure: false,
  auth: {
    user: process.env.MAILTRAP_USERNAME,
    pass: process.env.MAILTRAP_PASSWORD,
  },
});

export const sendEmail = async (options) => {
  try {
    const emailHtml = mailGenerator.generate(options.mailgenContent);
    const emailText = mailGenerator.generatePlaintext(options.mailgenContent);

    const mail = {
      from: process.env.MAILTRAP_MAIL || 'mail@freeapi.app',
      to: options.email,
      subject: options.subject,
      text: emailText,
      html: emailHtml,
    };

    await transporter.sendMail(mail);
    console.log('✅ Email sent to:', options.email);
  } catch (error) {
    console.error('❌ Email service failed:', error.message);
  }
};

export const emailVerificationMailgenContent = (username, verificationUrl) => ({
  body: {
    name: username,
    intro: "Welcome to our app! We're very excited to have you on board.",
    action: {
      instructions: 'To verify your email, click the button below:',
      button: {
        color: '#22BC66',
        text: 'Verify Email',
        link: verificationUrl,
      },
    },
    outro: "Need help? Just reply to this email. We're here to help.",
  },
});
