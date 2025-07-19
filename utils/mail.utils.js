import nodemailer from 'nodemailer';
import Mailgen from 'mailgen';

import { EMAIL } from './constants.utils.js';

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
  host: EMAIL.emailHost,
  port: parseInt(EMAIL.emailPort, 10),
  secure: false,
  auth: {
    user: EMAIL.authUser,
    pass: EMAIL.authPass,
  },
});

export const sendEmail = async (options) => {
  try {
    const emailHtml = mailGenerator.generate(options.mailgenContent);
    const emailText = mailGenerator.generatePlaintext(options.mailgenContent);

    const mail = {
      from: EMAIL.emailFrom || 'mail@freeapi.app',
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

export const resetPasswordMailgenContent = (username, resetUrl) => ({
  body: {
    name: username,
    intro: "You recently requested to reset your password.",
    action: {
      instructions: "Click the button below to set a new password:",
      button: {
        color: '#22BC66',
        text: 'Reset Password',
        link: resetUrl,
      },
    },
    outro: "If you did not request a password reset, please ignore this email or contact support if you have concerns.",
  },
});

