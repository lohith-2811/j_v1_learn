import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { initDB, getDB } from './db.js';
import cors from 'cors';
import nodemailer from 'nodemailer';
import fs from 'fs';
import admin from 'firebase-admin';
import { v4 as uuidv4 } from 'uuid';

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const REQUIRE_EMAIL_VERIFICATION = process.env.REQUIRE_EMAIL_VERIFICATION === 'true';

// In production, use Redis instead of in-memory Set
const activeTokens = new Set();

// Firebase Admin SDK Initialization
let firebaseCredentials;
try {
  firebaseCredentials = JSON.parse(process.env.FIREBASE_CREDENTIALS);
} catch (error) {
  console.error("Error parsing FIREBASE_CREDENTIALS:", error);
  process.exit(1);
}

// Initialize Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(firebaseCredentials)
});

const firebaseInitialized = true;

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Helper function to get current IST time
function getISTTimestamp() {
  const now = new Date();
  const ISTOffset = 330; // IST is UTC+5:30 (5*60 + 30 = 330 minutes)
  const ISTTime = new Date(now.getTime() + (ISTOffset - now.getTimezoneOffset()) * 60000);
  return ISTTime.toISOString().replace('T', ' ').replace('.000Z', '');
}


// Schedule cleanup of vouchers (runs every hour)
setInterval(async () => {
  try {
    const db = getDB();
    const oneDayBefore = Date.now() + 24 * 60 * 60 * 1000; // One day from now
    // Delete from stock one day before expire_date
    await db.execute({
      sql: 'DELETE FROM stock WHERE expire_date < ?',
      args: [oneDayBefore]
    });
    // Delete expired from user_vouchers
    await db.execute({
      sql: 'DELETE FROM user_vouchers WHERE expire_date < ?',
      args: [Date.now()]
    });
    console.log('Expired vouchers deleted at', getISTTimestamp());
  } catch (err) {
    console.error('Error deleting expired vouchers at', getISTTimestamp(), ':', err);
  }
}, 60 * 60 * 1000); // Every hour


// Health check endpoint with IST timestamp
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    message: 'JLearn API with persistent sessions',
    timestamp: getISTTimestamp(),
    features: {
      googleSignIn: firebaseInitialized,
      persistentSessions: true,
      requireEmailVerification: REQUIRE_EMAIL_VERIFICATION,
      emailService: !!process.env.EMAIL_USER && !!process.env.EMAIL_PASS
    }
  });
});

// Initialize database
(async () => {
  try {
    await initDB();
    console.log('Database initialized successfully at', getISTTimestamp());
  } catch (err) {
    console.error('Database initialization failed at', getISTTimestamp(), ':', err);
    process.exit(1);
  }
})();

// Enhanced Authentication Middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization || req.query.token;

  if (!authHeader) {
    return res.status(401).json({
      error: 'Authorization header missing',
      timestamp: getISTTimestamp()
    });
  }

  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;

  // Check if token was invalidated
  if (!activeTokens.has(token)) {
    return res.status(403).json({
      error: 'Session terminated. Please login again.',
      timestamp: getISTTimestamp()
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error at', getISTTimestamp(), ':', err);
      return res.status(403).json({
        error: 'Invalid or malformed token',
        timestamp: getISTTimestamp()
      });
    }
    req.user = user;
    next();
  });
};

// Email sender
export const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

export const sendOTP = async (to, otp, purpose = 'email verification') => {
  try {
    const subject = purpose === 'password reset' ? 'Reset Your JLearn Password' : 'Verify Your Email with Jairisys';
    
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap" rel="stylesheet">
        <style>
          body {
            margin: 0;
            padding: 0;
            font-family: 'Poppins', sans-serif;
            background-color: #f7f9fc;
            color: #333;
          }
          .container {
            max-width: 600px;
            margin: 20px auto;
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
          }
          .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 30px;
            text-align: center;
            color: white;
          }
          .logo {
            font-size: 24px;
            font-weight: 700;
            margin-bottom: 10px;
          }
          .content {
            padding: 30px;
          }
          .otp-container {
            background: #f0f4ff;
            border-radius: 8px;
            padding: 20px;
            margin: 25px 0;
            text-align: center;
          }
          .otp-code {
            font-size: 32px;
            font-weight: 700;
            letter-spacing: 5px;
            color: #2c3e50;
            margin: 15px 0;
            padding: 10px 20px;
            background: white;
            border-radius: 6px;
            display: inline-block;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
          }
          .footer {
            background: #f0f4ff;
            padding: 20px;
            text-align: center;
            font-size: 12px;
            color: #7f8c8d;
          }
          .warning {
            color: #e74c3c;
            font-weight: 600;
            margin-top: 20px;
            padding: 10px;
            background: #fde8e8;
            border-radius: 6px;
            text-align: center;
          }
          .divider {
            height: 1px;
            background: linear-gradient(to right, transparent, #ddd, transparent);
            margin: 25px 0;
          }
          .btn {
            display: inline-block;
            padding: 12px 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            margin-top: 15px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">Jairisys</div>
            <h2>${purpose === 'password reset' ? 'Password Reset' : 'Account Verification'}</h2>
          </div>
          
          <div class="content">
            <p>Hello,</p>
            
            <p>${purpose === 'password reset' 
              ? 'You requested to reset your password. Use the following OTP to proceed:'
              : 'Thank you for signing up! Please verify your account using this OTP:'}</p>
            
            <div class="otp-container">
              <p>Your One-Time Password</p>
              <div class="otp-code">${otp}</div>
              <p>Valid for 10 minutes only</p>
            </div>
            
            ${purpose !== 'password reset' 
              ? '<div class="warning">Please verify within this time, or your account will be deleted.</div>'
              : ''}
            
            <div class="divider"></div>
            
            <p>If you didn\'t request this, please ignore this email or contact support if you have questions.</p>
            
            <p>Best regards,<br>Jairisys Team</p>
          </div>
          
          <div class="footer">
            © ${new Date().getFullYear()} Jairisys.tech. All rights reserved.
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
      Jairisys ${purpose === 'password reset' ? 'Password Reset' : 'Account Verification'}

      Hello,

      ${purpose === 'password reset' 
        ? 'You requested to reset your password. Use the following OTP to proceed:'
        : 'Thank you for signing up! Please verify your account using this OTP:'}

      OTP: ${otp}
      Valid for 10 minutes only

      ${purpose !== 'password reset' 
        ? 'Please verify within this time, or your account will be deleted.'
        : ''}

      If you didn't request this, please ignore this email or contact support if you have questions.

      Best regards,
      Jairisys Team

      © ${new Date().getFullYear()} Jairisys.tech. All rights reserved.
    `;

    const info = await transporter.sendMail({
      from: `"Jairisys" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html,
      text,
    });
    console.log(`OTP email sent successfully to ${to} for ${purpose}. Message ID:`, info.messageId);
    return info;
  } catch (err) {
    console.error(`Failed to send OTP email to ${to} for ${purpose}:`, err);
    console.warn(`OTP for testing (check database or resend): ${otp}`);
    throw new Error(`Failed to send OTP: ${err.message}`);
  }
};


// Voucher email sender
export const sendVoucherEmail = async (to, voucherDetails) => {
  const { voucherName, voucherCode, expireDate } = voucherDetails;
  try {
    const expireDateFormatted = new Date(expireDate).toLocaleString('en-IN', {
      timeZone: 'Asia/Kolkata',
      dateStyle: 'medium',
      timeStyle: 'short',
    });

    const subject = `Order Confirmed: Your ${voucherName} voucher has been successfully redeemed!`;
    const html = `
     <!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link href="https://fonts.googleapis.com/css2?family=Pacifico&family=PT+Serif&family=Satisfy&display=swap" rel="stylesheet">
  <style>
    body { margin: 0; padding: 0; font-family: 'PT Serif', serif; background-color: #f5f5f5; }
    .container { max-width: 400px; margin: 20px auto; background-color: #000000; padding: 16px; }
    .card { background: #ffffff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.2); overflow: hidden; position: relative; }
    .top-section { background: linear-gradient(180deg, #ffffff 0%, #e0f2e9 100%); padding: 20px; text-align: center; border-bottom: 2px dashed #14803C; }
    .voucher-name { font-family: 'Pacifico', cursive; font-size: 26px; color: #000000; margin: 0; }
    .expiry-date { font-family: 'PT Serif', serif; font-size: 14px; color: #555555; margin-top: 10px; }
    .value { font-family: 'PT Serif', serif; font-size: 18px; font-weight: bold; color: #14803C; margin-top: 5px; }
    .zigzag-divider { height: 12px; background: repeating-linear-gradient(45deg, #14803C, #14803C 10px, transparent 10px, transparent 20px); }
    .bottom-section { background: #4CAF50; padding: 20px; text-align: center; }
    .voucher-code { font-family: 'Courier New', monospace; font-size: 24px; font-weight: bold; letter-spacing: 2px; color: #FFFFFF; margin: 0; background: rgba(0,0,0,0.1); padding: 8px; border-radius: 4px; }
    .validity { margin-top: 16px; text-align: center; color: #FFFFFF; font-family: 'Satisfy', cursive; font-size: 14px; }
    .validity img { vertical-align: middle; margin-right: 8px; }
    .terms { padding: 15px; font-size: 12px; color: #666; text-align: center; border-top: 1px dashed #ccc; }
    .perforation { 
      position: absolute; 
      bottom: 50px; 
      left: 0; 
      right: 0; 
      height: 10px; 
      background: 
        linear-gradient(to right, #f5f5f5 0%, #f5f5f5 50%, transparent 50%, transparent 100%),
        linear-gradient(to right, black 0%, black 50%, transparent 50%, transparent 100%);
      background-size: 20px 2px, 20px 2px;
      background-position: 0 0, 0 4px;
      background-repeat: repeat-x;
    }
    .tear-off { 
      background: #f5f5f5; 
      padding: 15px; 
      text-align: center; 
      font-size: 12px; 
      color: #888;
      border-bottom-left-radius: 8px;
      border-bottom-right-radius: 8px;
    }
    .corner { 
      position: absolute; 
      width: 30px; 
      height: 30px; 
      background: #f5f5f5; 
      border-radius: 50%; 
      top: -15px; 
      right: -15px; 
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="corner"></div>
      <div class="top-section">
        <h1 class="voucher-name">${voucherName}</h1>
        <p class="expiry-date">Valid until: ${expireDateFormatted}</p>
      </div>
      
      <div class="perforation"></div>
      
      <div class="bottom-section">
        <p>YOUR PROMO CODE</p>
        <p class="voucher-code">${voucherCode}</p>
        <div class="validity">
          <span>Valid once per customer</span>
        </div>
      </div>
      
      <div class="terms">
        * Terms and conditions apply. Not valid with other offers. 
        Present this voucher at checkout to redeem.
      </div>
    </div>
    
    <div class="tear-off">
      <p>Jairisys.tech</p>
    </div>
  </div>
</body>
</html>
    `;

    const text = `
      Voucher Redeemed Successfully!

      Dear User,

      You have successfully redeemed a voucher. Here are the details:
      - Voucher Name: ${voucherName}
      - Voucher Code: ${voucherCode}
      - Expires On: ${expireDateFormatted}
      - Valid once per user

      Please use this voucher before it expires. Contact support if you have any issues.

      Best regards,
      Jairisys Team
    `;

    const info = await transporter.sendMail({
      from: `"JLearn" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html,
      text,
    });

    console.log(`Voucher email sent successfully to ${to}. Message ID:`, info.messageId);
    return info;
  } catch (err) {
    console.error(`Failed to send voucher email to ${to}:`, err);
    throw new Error(`Failed to send voucher email: ${err.message}`);
  }
};



// Signup welcome
export const sendWelcomeEmail = async (to, username) => {
  try {
    const subject = 'Welcome to Jairisys!';
    
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap" rel="stylesheet">
        <style>
          body {
            margin: 0;
            padding: 0;
            font-family: 'Poppins', sans-serif;
            background-color: #f7f9fc;
            color: #333;
          }
          .container {
            max-width: 600px;
            margin: 20px auto;
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
          }
          .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 30px;
            text-align: center;
            color: white;
          }
          .logo {
            font-size: 24px;
            font-weight: 700;
            margin-bottom: 10px;
          }
          .content {
            padding: 30px;
          }
          .welcome-container {
            background: #f0f4ff;
            border-radius: 8px;
            padding: 20px;
            margin: 25px 0;
            text-align: center;
          }
          .welcome-title {
            font-size: 24px;
            font-weight: 600;
            color: #2c3e50;
            margin: 15px 0;
          }
          .footer {
            background: #f0f4ff;
            padding: 20px;
            text-align: center;
            font-size: 12px;
            color: #7f8c8d;
          }
          .divider {
            height: 1px;
            background: linear-gradient(to right, transparent, #ddd, transparent);
            margin: 25px 0;
          }
          .btn {
            display: inline-block;
            padding: 12px 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            margin-top: 15px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">Jairisys</div>
            <h2>Welcome Aboard!</h2>
          </div>
          
          <div class="content">
            <p>Hello${username ? `, ${username}` : ''},</p>
            
            <p>Welcome to Jairisys! We're thrilled to have you join our learning community. Get ready to explore a world of knowledge and enhance your skills with our interactive courses.</p>
            
            <div class="welcome-container">
              <div class="welcome-title">Your Journey Starts Here</div>
              <p>Log in now to start learning and earn rewards!</p>
              <a href="https://jairisys.tech/login" class="btn">Start Learning</a>
            </div>
            
            <div class="divider"></div>
            
            <p>If you have any questions or need assistance, feel free to contact our support team.</p>
            
            <p>Best regards,<br>Jairisys Team</p>
          </div>
          
          <div class="footer">
            © ${new Date().getFullYear()} Jairisys.tech. All rights reserved.
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
      Welcome to Jairisys!

      Hello${username ? `, ${username}` : ''},

      Welcome to Jairisys! We're thrilled to have you join our learning community. Get ready to explore a world of knowledge and enhance your skills with our interactive courses.

      Your Journey Starts Here
      Log in now to start learning and earn rewards! Visit: https://jairisys.tech/login

      If you have any questions or need assistance, feel free to contact our support team.

      Best regards,
      Jairisys Team

      © ${new Date().getFullYear()} Jairisys.tech. All rights reserved.
    `;

    const info = await transporter.sendMail({
      from: `"Jairisys" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html,
      text,
    });
    console.log(`Welcome email sent successfully to ${to}. Message ID:`, info.messageId);
    return info;
  } catch (err) {
    console.error(`Failed to send welcome email to ${to}:`, err);
    throw new Error(`Failed to send welcome email: ${err.message}`);
  }
};




// Google Sign-In (Firebase Auth) Endpoint
app.post('/auth/google', async (req, res) => {
  if (!firebaseInitialized) {
    return res.status(501).json({
      success: false,
      error: 'Google Sign-In is not configured on this server',
      timestamp: getISTTimestamp()
    });
  }

  const { token: firebaseToken } = req.body;

  if (!firebaseToken) {
    return res.status(400).json({
      error: 'Firebase ID token is required',
      timestamp: getISTTimestamp()
    });
  }

  try {
    // Verify Firebase ID token
    const decodedToken = await admin.auth().verifyIdToken(firebaseToken);
    const { uid, email } = decodedToken;

    const db = getDB();

    // Check if user exists
    let user = await db.execute({
      sql: 'SELECT user_id, username, email FROM user_profiles WHERE email = ?',
      args: [email],
    });

    if (user.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found. Please sign up first using email/password.',
        timestamp: getISTTimestamp()
      });
    }

    const userId = user.rows[0].user_id;
    const username = user.rows[0].username;

    // Update last login
    await db.execute({
      sql: 'UPDATE user_profiles SET last_login = ? WHERE user_id = ?',
      args: [getISTTimestamp(), userId],
    });

    // Generate JWT
    const appToken = jwt.sign(
      { id: userId, email, username },
      JWT_SECRET
    );

    activeTokens.add(appToken);

    res.json({
      success: true,
      token: appToken,
      user: {
        id: userId,
        username,
        email,
        isGoogleAuth: true
      },
      timestamp: getISTTimestamp()
    });

  } catch (err) {
    console.error('Firebase auth error at', getISTTimestamp(), ':', err);
    res.status(401).json({
      error: 'Invalid Firebase ID token',
      timestamp: getISTTimestamp()
    });
  }
});

// Regular Email/Password Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const loginTime = getISTTimestamp();

  if (!email || !password) {
    return res.status(400).json({
      error: 'Email and password are required',
      timestamp: loginTime
    });
  }

  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT user_id, username, email, password_hash, is_google_auth, is_verified FROM user_profiles WHERE email = ?',
      args: [email],
    });

    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({
        error: 'Invalid credentials',
        timestamp: loginTime
      });
    }

    // Check if user registered via Google
    if (user.is_google_auth) {
      return res.status(403).json({
        error: 'This account uses Google Sign-In. Please sign in with Google.',
        timestamp: loginTime
      });
    }

    // Check email verification if required
    if (REQUIRE_EMAIL_VERIFICATION && !user.is_verified) {
      return res.status(403).json({
        error: 'Email not verified. Please verify your email to log in.',
        timestamp: loginTime
      });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({
        error: 'Invalid credentials',
        timestamp: loginTime
      });
    }

    // Update last login
    await db.execute({
      sql: 'UPDATE user_profiles SET last_login = ? WHERE user_id = ?',
      args: [loginTime, user.user_id],
    });

    const token = jwt.sign(
      { id: user.user_id, email: user.email, username: user.username },
      JWT_SECRET
    );

    activeTokens.add(token);

    res.json({
      success: true,
      token,
      user: {
        id: user.user_id,
        username: user.username,
        email: user.email,
        isGoogleAuth: false,
        isVerified: user.is_verified
      },
      timestamp: loginTime
    });
  } catch (err) {
    console.error('Login error at', getISTTimestamp(), ':', err);
    res.status(500).json({
      error: 'Login failed',
      timestamp: getISTTimestamp()
    });
  }
});

// Email/Password Signup
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  const signupTime = getISTTimestamp();

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required', timestamp: signupTime });
  }

  try {
    const db = getDB();

    const checkUser = await db.execute({
      sql: 'SELECT * FROM user_profiles WHERE email = ?',
      args: [email],
    });

    if (checkUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered', timestamp: signupTime });
    }

    // Hash the password
    const passwordHash = await bcrypt.hash(password, 10);

    // Calculate expiration time (10 minutes from now)
    const expiresAt = Date.now() + 10 * 60 * 1000;

    // Insert user with expiration time
    await db.execute({
      sql: 'INSERT INTO user_profiles (username, email, password_hash, is_verified, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
      args: [username, email, passwordHash, false, signupTime, expiresAt],
    });

    // Generate and store OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await db.execute({
      sql: 'INSERT OR REPLACE INTO user_otp_verification (email, otp, expires_at, created_at) VALUES (?, ?, ?, ?)',
      args: [email, otp, expiresAt, signupTime],
    });

    // Schedule deletion of unverified user after 10 minutes
    setTimeout(async () => {
      try {
        const result = await db.execute({
          sql: 'SELECT is_verified FROM user_profiles WHERE email = ?',
          args: [email],
        });

        if (result.rows.length > 0 && !result.rows[0].is_verified) {
          await db.execute({
            sql: 'DELETE FROM user_profiles WHERE email = ?',
            args: [email],
          });
          await db.execute({
            sql: 'DELETE FROM user_otp_verification WHERE email = ?',
            args: [email],
          });
          console.log(`Deleted unverified user ${email} at ${getISTTimestamp()}`);
        }
      } catch (err) {
        console.error(`Error deleting unverified user ${email} at ${getISTTimestamp()}:`, err);
      }
    }, 10 * 60 * 1000); // 10 minutes

    try {
      await sendOTP(email, otp);
      res.status(200).json({
        success: true,
        message: 'Signup successful. OTP sent to your email. Please verify within 10 minutes.',
        timestamp: signupTime,
      });
    } catch (emailErr) {
      console.warn('Signup successful, but OTP email failed to send for', email);
      console.warn('OTP for testing (check database or resend):', otp);
      res.status(200).json({
        success: true,
        message: 'Signup successful, but OTP email failed to send. OTP logged to console and stored in database. Please verify within 10 minutes.',
        timestamp: signupTime,
      });
    }
  } catch (err) {
    console.error('Signup error at', signupTime, ':', err);
    res.status(500).json({ error: 'Signup failed: ' + err.message, timestamp: signupTime });
  }
});

// Verify OTP
app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  const verifyTime = getISTTimestamp();

  if (!email || !otp) {
    return res.status(400).json({ error: 'Email and OTP are required', timestamp: verifyTime });
  }

  try {
    const db = getDB();

    // Check if user exists
    const userResult = await db.execute({
      sql: 'SELECT user_id, username, is_verified FROM user_profiles WHERE email = ?',
      args: [email],
    });

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found. Account may have been deleted due to unverified status.', timestamp: verifyTime });
    }

    const user = userResult.rows[0];
    if (user.is_verified) {
      return res.status(400).json({ error: 'Email already verified', timestamp: verifyTime });
    }

    const result = await db.execute({
      sql: 'SELECT otp, expires_at FROM user_otp_verification WHERE email = ?',
      args: [email],
    });

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'No OTP found for this email', timestamp: verifyTime });
    }

    const storedOTP = result.rows[0].otp;
    const expiresAt = result.rows[0].expires_at;

    if (Date.now() > expiresAt) {
      // Delete user and OTP if expired
      await db.execute({
        sql: 'DELETE FROM user_profiles WHERE email = ?',
        args: [email],
      });
      await db.execute({
        sql: 'DELETE FROM user_otp_verification WHERE email = ?',
        args: [email],
      });
      return res.status(400).json({ error: 'OTP expired. Account deleted. Please sign up again.', timestamp: verifyTime });
    }

    if (otp !== storedOTP) {
      return res.status(400).json({ error: 'Invalid OTP', timestamp: verifyTime });
    }

    // Mark user as verified and clear expiration
    await db.execute({
      sql: 'UPDATE user_profiles SET is_verified = ?, expires_at = NULL WHERE email = ?',
      args: [true, email],
    });

    await db.execute({
      sql: 'DELETE FROM user_otp_verification WHERE email = ?',
      args: [email],
    });

    // Send welcome email
    try {
      await sendWelcomeEmail(email, user.username);
      console.log(`Welcome email sent to ${email} after verification at ${verifyTime}`);
    } catch (emailErr) {
      console.warn(`Verification successful, but welcome email failed to send for ${email}:`, emailErr);
    }

    res.status(200).json({ success: true, message: 'Email verified successfully', timestamp: verifyTime });
  } catch (err) {
    console.error('Verification error at', verifyTime, ':', err);
    res.status(500).json({ error: 'OTP verification failed: ' + err.message, timestamp: verifyTime });
  }
});

// Forgot Password Endpoint
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const requestTime = getISTTimestamp();

  if (!email) {
    return res.status(400).json({ error: 'Email is required', timestamp: requestTime });
  }

  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT user_id, is_google_auth FROM user_profiles WHERE email = ?',
      args: [email],
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Email not found', timestamp: requestTime });
    }

    const user = result.rows[0];
    if (user.is_google_auth) {
      return res.status(400).json({
        error: 'This account uses Google Sign-In. Password reset is not applicable.',
        timestamp: requestTime,
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    await db.execute({
      sql: 'INSERT OR REPLACE INTO user_otp_verification (email, otp, expires_at, created_at) VALUES (?, ?, ?, ?)',
      args: [email, otp, expiresAt, requestTime],
    });

    try {
      await sendOTP(email, otp, 'password reset');
      res.status(200).json({
        success: true,
        message: 'Password reset OTP sent to your email.',
        timestamp: requestTime,
      });
    } catch (emailErr) {
      console.warn('Password reset OTP generated, but email failed to send for', email);
      console.warn('OTP for testing (check database or resend):', otp);
      res.status(200).json({
        success: true,
        message: 'Password reset OTP generated, but email failed to send. OTP logged to console and stored in database. Please check or request a new OTP.',
        timestamp: requestTime,
      });
    }
  } catch (err) {
    console.error('Forgot password error at', requestTime, ':', err);
    res.status(500).json({ error: 'Failed to process password reset request: ' + err.message, timestamp: requestTime });
  }
});

// Reset Password Endpoint
app.post('/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  const resetTime = getISTTimestamp();

  if (!email || !otp || !newPassword) {
    return res.status(400).json({ error: 'Email, OTP, and new password are required', timestamp: resetTime });
  }

  try {
    const db = getDB();

    const otpResult = await db.execute({
      sql: 'SELECT otp, expires_at FROM user_otp_verification WHERE email = ?',
      args: [email],
    });

    if (otpResult.rows.length === 0) {
      return res.status(400).json({ error: 'No OTP found for this email', timestamp: resetTime });
    }

    const storedOTP = otpResult.rows[0].otp;
    const expiresAt = otpResult.rows[0].expires_at;

    if (Date.now() > expiresAt) {
      await db.execute({
        sql: 'DELETE FROM user_otp_verification WHERE email = ?',
        args: [email],
      });
      return res.status(400).json({ error: 'OTP expired', timestamp: resetTime });
    }

    if (otp !== storedOTP) {
      return res.status(400).json({ error: 'Invalid OTP', timestamp: resetTime });
    }

    const userResult = await db.execute({
      sql: 'SELECT user_id, is_google_auth FROM user_profiles WHERE email = ?',
      args: [email],
    });

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found', timestamp: resetTime });
    }

    const user = userResult.rows[0];
    if (user.is_google_auth) {
      return res.status(400).json({
        error: 'This account uses Google Sign-In. Password reset is not applicable.',
        timestamp: resetTime,
      });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);

    await db.execute({
      sql: 'UPDATE user_profiles SET password_hash = ? WHERE email = ?',
      args: [passwordHash, email],
    });

    await db.execute({
      sql: 'DELETE FROM user_otp_verification WHERE email = ?',
      args: [email],
    });

    // Invalidate all active tokens for this user
    const tokensToRemove = [...activeTokens].filter(token => {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return decoded.email === email;
      } catch {
        return false;
      }
    });
    tokensToRemove.forEach(token => activeTokens.delete(token));

    res.status(200).json({
      success: true,
      message: 'Password reset successfully. All active sessions have been invalidated.',
      timestamp: resetTime,
    });
  } catch (err) {
    console.error('Reset password error at', resetTime, ':', err);
    res.status(500).json({ error: 'Failed to reset password: ' + err.message, timestamp: resetTime });
  }
});

// Resend OTP
app.post('/resend-otp', async (req, res) => {
  const { email } = req.body;
  const resendTime = getISTTimestamp();

  if (!email) {
    return res.status(400).json({ error: 'Email is required', timestamp: resendTime });
  }

  try {
    const db = getDB();

    const result = await db.execute({
      sql: 'SELECT is_verified, expires_at FROM user_profiles WHERE email = ?',
      args: [email],
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found. Account may have been deleted due to unverified status.', timestamp: resendTime });
    }

    if (result.rows[0].is_verified) {
      return res.status(400).json({ error: 'Email already verified', timestamp: resendTime });
    }

    if (Date.now() > result.rows[0].expires_at) {
      // Delete user and OTP if expired
      await db.execute({
        sql: 'DELETE FROM user_profiles WHERE email = ?',
        args: [email],
      });
      await db.execute({
        sql: 'DELETE FROM user_otp_verification WHERE email = ?',
        args: [email],
      });
      return res.status(400).json({ error: 'Verification period expired. Account deleted. Please sign up again.', timestamp: resendTime });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    await db.execute({
      sql: 'INSERT OR REPLACE INTO user_otp_verification (email, otp, expires_at, created_at) VALUES (?, ?, ?, ?)',
      args: [email, otp, expiresAt, resendTime],
    });

    try {
      await sendOTP(email, otp);
      res.status(200).json({ success: true, message: 'OTP resent successfully. Please verify within 10 minutes.', timestamp: resendTime });
    } catch (emailErr) {
      console.warn('OTP generated, but email failed to send for', email);
      console.warn('OTP for testing (check database or resend):', otp);
      res.status(200).json({
        success: true,
        message: 'OTP generated, but email failed to send. OTP logged to console and stored in database. Please verify within 10 minutes.',
        timestamp: resendTime,
      });
    }
  } catch (err) {
    console.error('Resend OTP error at', resendTime, ':', err);
    res.status(500).json({ error: 'Failed to resend OTP: ' + err.message, timestamp: resendTime });
  }
});

// Explicit logout endpoint
app.post('/logout', authenticateJWT, (req, res) => {
  const token = req.headers.authorization.slice(7);
  const logoutTime = getISTTimestamp();

  // Remove token from active set
  activeTokens.delete(token);

  res.json({
    success: true,
    message: 'Logged out successfully. Token invalidated.',
    timestamp: logoutTime
  });
});

// Emergency token invalidation (for app uninstall/data clear)
app.post('/invalidate-all', async (req, res) => {
  const { email, password } = req.body;
  const invalidationTime = getISTTimestamp();

  if (!email || !password) {
    return res.status(400).json({
      error: 'Email and password are required',
      timestamp: invalidationTime
    });
  }

  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT user_id FROM user_profiles WHERE email = ?',
      args: [email],
    });

    const user = result.rows[0];
    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        timestamp: invalidationTime
      });
    }

    // Verify password
    const pwResult = await db.execute({
      sql: 'SELECT password_hash FROM user_profiles WHERE user_id = ?',
      args: [user.user_id],
    });

    const isMatch = await bcrypt.compare(password, pwResult.rows[0].password_hash);
    if (!isMatch) {
      return res.status(401).json({
        error: 'Invalid credentials',
        timestamp: invalidationTime
      });
    }

    // In production: Query all tokens for this user from Redis/db and remove
    activeTokens.clear();

    res.json({
      success: true,
      message: 'All sessions invalidated successfully',
      timestamp: invalidationTime
    });
  } catch (err) {
    console.error('Invalidation error at', getISTTimestamp(), ':', err);
    res.status(500).json({
      error: 'Session invalidation failed',
      timestamp: getISTTimestamp()
    });
  }
});

// Protected progress update endpoint
app.post('/progress', authenticateJWT, async (req, res) => {
  const { language, level, module_id, lesson_id, is_completed, current_question_index } = req.body;
  const updateTime = getISTTimestamp();

  if (!language || level === undefined || module_id === undefined || lesson_id === undefined) {
    return res.status(400).json({
      error: 'Missing required fields',
      timestamp: updateTime
    });
  }

  try {
    const db = getDB();
    const bitPosition = 1 << (lesson_id - 1);
    const maskUpdate = is_completed ? bitPosition : 0;

    await db.execute({
      sql: `
        INSERT INTO user_module_progress 
          (user_id, language, level, module_id, completion_mask, 
           current_lesson_id, current_question_index, last_updated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, language, level, module_id) 
        DO UPDATE SET
          completion_mask = CASE 
            WHEN ? = 0 THEN completion_mask & ~?
            ELSE completion_mask | ?
          END,
          current_lesson_id = excluded.current_lesson_id,
          current_question_index = excluded.current_question_index,
          last_updated = ?
      `,
      args: [
        req.user.id,
        language,
        level,
        module_id,
        maskUpdate,
        lesson_id,
        current_question_index || 0,
        updateTime,
        maskUpdate,
        bitPosition,
        bitPosition,
        updateTime
      ],
    });

    res.json({
      success: true,
      message: 'Progress updated successfully',
      timestamp: updateTime
    });
  } catch (err) {
    console.error('Progress update error at', getISTTimestamp(), ':', err);
    res.status(500).json({
      error: 'Failed to update progress',
      timestamp: getISTTimestamp()
    });
  }
});

app.get('/progress', authenticateJWT, async (req, res) => {
  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT * FROM user_module_progress WHERE user_id = ?',
      args: [req.user.id],
    });

    res.json({
      success: true,
      progress: result.rows
    });
  } catch (err) {
    console.error('Progress fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch progress' });
  }
});


//Achievements endpoint
app.post('/achievements/add-xp', authenticateJWT, async (req, res) => {
  const { xp } = req.body;
  if (!xp || typeof xp !== 'number' || xp <= 0) {
    return res.status(400).json({ success: false, error: 'XP must be a positive number' });
  }
  try {
    const db = getDB();
    await db.execute({
      sql: `
        INSERT INTO user_achievements (user_id, xp_points)
        VALUES (?, ?)
        ON CONFLICT(user_id) DO UPDATE SET xp_points = xp_points + ?
      `,
      args: [req.user.id, xp, xp]
    });
    res.json({ success: true, message: `${xp} XP added successfully` });
  } catch (err) {
    console.error('Error adding XP:', err);
    res.status(500).json({ success: false, error: 'Failed to add XP' });
  }
});


// XP achievements endpoint
app.get('/achievements', authenticateJWT, async (req, res) => {
  try {
    const db = getDB();
    const { rows } = await db.execute({
      sql: 'SELECT xp_points FROM user_achievements WHERE user_id = ?',
      args: [req.user.id]
    });
    res.json({ success: true, xp_points: rows[0]?.xp_points || 0 });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to fetch achievements' });
  }
});


// Get user profile
app.get('/profile', authenticateJWT, async (req, res) => {
  try {
    // Validate user ID
    if (!req.user.id) {
      return res.status(400).json({
        error: 'Invalid user ID',
        timestamp: getISTTimestamp()
      });
    }

    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT user_id, username, email, is_google_auth, created_at, last_login, is_verified FROM user_profiles WHERE user_id = ?',
      args: [req.user.id]
    });

    const user = result.rows[0];
    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        timestamp: getISTTimestamp()
      });
    }

    res.json({
      success: true,
      message: 'Profile fetched successfully',
      profile: {
        id: user.user_id,
        username: user.username,
        email: user.email,
        isGoogleAuth: user.is_google_auth,
        createdAt: user.created_at,
        lastLogin: user.last_login,
        isVerified: user.is_verified
      },
      timestamp: getISTTimestamp()
    });
  } catch (err) {
    console.error('Profile fetch error at', getISTTimestamp(), ':', err);
    res.status(500).json({
      error: 'Failed to fetch profile',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined,
      timestamp: getISTTimestamp()
    });
  }
});

// Save Switched Course
app.post('/save-switched-course', authenticateJWT, async (req, res) => {
  const { courseId, language } = req.body;
  const saveTime = getISTTimestamp();

  if (!courseId || !language) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: courseId, language',
      timestamp: saveTime
    });
  }

  try {
    const db = getDB();

    // Determine the latest level from user_module_progress
    const progressResult = await db.execute({
      sql: 'SELECT MAX(level) as max_level FROM user_module_progress WHERE user_id = ? AND language = ?',
      args: [req.user.id, language]
    });

    let level = 1; // Default to level 1
    if (progressResult.rows.length > 0 && progressResult.rows[0].max_level !== null) {
      level = progressResult.rows[0].max_level;
      // Check if the next level exists in lesson_details
      const nextLevelResult = await db.execute({
        sql: 'SELECT level FROM lesson_details WHERE language = ? AND level = ?',
        args: [language, level + 1]
      });
      if (nextLevelResult.rows.length > 0) {
        level += 1; // Move to the next level if available
      }
    }

    // Upsert the switched course
    await db.execute({
      sql: `
        INSERT INTO user_switched_course (user_id, course_id, language, level, switched_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          course_id = excluded.course_id,
          language = excluded.language,
          level = excluded.level,
          switched_at = excluded.switched_at
      `,
      args: [req.user.id, courseId, language, level, saveTime]
    });

    res.json({
      success: true,
      message: 'Switched course saved successfully',
      level: level, // Return the assigned level for frontend use
      timestamp: saveTime
    });
  } catch (err) {
    console.error('Save switched course error at', saveTime, ':', err);
    res.status(500).json({
      success: false,
      error: 'Failed to save switched course',
      timestamp: saveTime
    });
  }
});

// Get Switched Course
app.get('/switched-course', authenticateJWT, async (req, res) => {
  const getTime = getISTTimestamp();
  try {
    const db = getDB();
    const result = await db.execute({
      sql: `
        SELECT course_id, language, level, switched_at
        FROM user_switched_course
        WHERE user_id = ?
      `,
      args: [req.user.id]
    });

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'No switched course found for user',
        timestamp: getTime
      });
    }

    res.json({
      success: true,
      switchedCourse: result.rows[0],
      timestamp: getTime
    });
  } catch (err) {
    console.error('Get switched course error at', getTime, ':', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get switched course',
      timestamp: getTime
    });
  }
});

// Leaderboard endpoint: Return top users by XP
app.get('/leaderboard', authenticateJWT, async (req, res) => {
  try {
    const db = getDB();
    // Join profiles and achievements, show users with XP (default 0 if no row in user_achievements)
    const result = await db.execute({
      sql: `
        SELECT 
          u.user_id, 
          u.username, 
          u.email, 
          COALESCE(a.xp_points, 0) AS xp_points
        FROM user_profiles u
        LEFT JOIN user_achievements a ON u.user_id = a.user_id
        ORDER BY xp_points DESC, u.username ASC
        LIMIT 100
      `,
      args: [],
    });

    // You can filter out unverified users if needed:
    // WHERE u.is_verified = 1

    res.json({
      success: true,
      leaderboard: result.rows.map(row => ({
        user_id: row.user_id,
        username: row.username,
        email: row.email,
        xp: row.xp_points
      }))
    });
  } catch (err) {
    console.error('Leaderboard fetch error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch leaderboard'
    });
  }
});




// vouchers Endpoint
app.get('/vouchers', authenticateJWT, async (req, res) => {
  try {
    const db = getDB();
    // Group by voucher_name to get distinct vouchers with points_price
    const result = await db.execute({
      sql: `
        SELECT voucher_name, points_price
        FROM stock
        GROUP BY voucher_name, points_price
        HAVING COUNT(voucher_code) > 0
      `,
      args: []
    });
    res.json({
      success: true,
      vouchers: result.rows.map(row => ({
        voucher_name: row.voucher_name,
        points_price: row.points_price
      }))
    });
  } catch (err) {
    console.error('Fetch vouchers error at', getISTTimestamp(), ':', err);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch vouchers'
    });
  }
});

// Voucher redeem

app.post('/voucher/redeem', authenticateJWT, async (req, res) => {
  const { voucher_name } = req.body;
  const redeemTime = getISTTimestamp();

  if (!voucher_name) {
    return res.status(400).json({
      error: 'voucher_name is required',
      timestamp: redeemTime
    });
  }

  try {
    const db = getDB();

    // Fetch an available voucher code from stock
    const voucherResult = await db.execute({
      sql: `
        SELECT id, voucher_code, points_price, expire_date
        FROM stock
        WHERE voucher_name = ? AND expire_date > ?
        LIMIT 1
      `,
      args: [voucher_name, Date.now() + 24 * 60 * 60 * 1000]
    });

    if (voucherResult.rows.length === 0) {
      return res.status(404).json({
        error: 'No valid voucher available for this voucher name',
        timestamp: redeemTime
      });
    }

    const { id, voucher_code, points_price, expire_date } = voucherResult.rows[0];

    // Check user's XP balance
    const xpResult = await db.execute({
      sql: 'SELECT xp_points FROM user_achievements WHERE user_id = ?',
      args: [req.user.id]
    });

    const currentXp = xpResult.rows[0]?.xp_points || 0;
    if (currentXp < points_price) {
      return res.status(400).json({
        error: 'Insufficient XP points',
        timestamp: redeemTime
      });
    }

    // Deduct XP points
    await db.execute({
      sql: 'UPDATE user_achievements SET xp_points = xp_points - ? WHERE user_id = ?',
      args: [points_price, req.user.id]
    });

    // Store in user_vouchers
    await db.execute({
      sql: `
        INSERT INTO user_vouchers (user_id, voucher_name, voucher_code, expire_date)
        VALUES (?, ?, ?, ?)
      `,
      args: [req.user.id, voucher_name, voucher_code, expire_date]
    });

    // Delete from stock
    await db.execute({
      sql: 'DELETE FROM stock WHERE id = ?',
      args: [id]
    });

    // Fetch user's email from the user_profiles table
    const userResult = await db.execute({
      sql: 'SELECT email FROM user_profiles WHERE user_id = ?',
      args: [req.user.id]
    });

    const userEmail = userResult.rows[0]?.email;
    let emailSent = false;
    if (userEmail) {
      try {
        await sendVoucherEmail(userEmail, {
          voucherName: voucher_name,
          voucherCode: voucher_code,
          expireDate: expire_date
        });
        emailSent = true;
      } catch (emailErr) {
        console.warn(`Voucher redeemed, but email failed to send for ${userEmail}:`, emailErr);
      }
    }

    res.json({
      success: true,
      voucherCode: voucher_code,
      expiresAt: expire_date,
      message: emailSent
        ? 'Voucher redeemed successfully and email sent!'
        : 'Voucher redeemed successfully, but email failed to send. Please check your vouchers in the app.',
      timestamp: redeemTime
    });
  } catch (err) {
    console.error('Redeem voucher error at', redeemTime, ':', err);
    res.status(500).json({
      success: false,
      error: 'Failed to redeem voucher',
      timestamp: redeemTime
    });
  }
});

app.get('/user/vouchers', authenticateJWT, async (req, res) => {
  try {
    const db = getDB();
    const result = await db.execute({
      sql: `
        SELECT id, voucher_name, voucher_code, redeemed_at, expire_date
        FROM user_vouchers
        WHERE user_id = ? AND expire_date > ?
      `,
      args: [req.user.id, Date.now()]
    });

    res.json({
      success: true,
      vouchers: result.rows.map(row => ({
        id: row.id,
        voucher_name: row.voucher_name,
        voucher_code: row.voucher_code,
        redeemed_at: row.redeemed_at,
        expires_at: row.expire_date
      }))
    });
  } catch (err) {
    console.error('Fetch user vouchers error at', getISTTimestamp(), ':', err);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch user vouchers'
    });
  }
});


// Delete user account endpoint
app.delete('/account', authenticateJWT, async (req, res) => {
  const db = getDB();
  const userId = req.user.id;
  const userEmail = req.user.email;
  const deletionTime = getISTTimestamp();

  try {
    // Delete related data first (optional: uncomment if applicable)
    await db.execute({
      sql: 'DELETE FROM user_vouchers WHERE user_id = ?',
      args: [userId],
    });

    // Delete user profile
    const result = await db.execute({
      sql: 'DELETE FROM user_profiles WHERE user_id = ?',
      args: [userId],
    });

    // Invalidate the token (remove from activeTokens)
    const authHeader = req.headers.authorization || req.query.token;
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
    activeTokens.delete(token);

    console.log(`User account deleted: user_id=${userId}, email=${userEmail} at`, deletionTime);

    res.json({
      success: true,
      message: 'Your account has been deleted successfully.',
      timestamp: deletionTime
    });
  } catch (err) {
    console.error('Error deleting user account at', deletionTime, ':', err);
    res.status(500).json({
      error: 'Failed to delete account. Please try again later.',
      timestamp: deletionTime
    });
  }
});


// Start server
app.listen(PORT, () => {
  console.log(`Server started at ${getISTTimestamp()} on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log('Features enabled:');
  console.log('- Persistent JWT sessions');
  console.log('- Google Sign-In:', firebaseInitialized ? 'Enabled' : 'Disabled');
  console.log('- Indian Standard Time (IST) timestamps');
  console.log('- Bitmask progress tracking');
  console.log('- Email verification required:', REQUIRE_EMAIL_VERIFICATION);
  console.log('- Email service configured:', !!process.env.EMAIL_USER && !!process.env.EMAIL_PASS);
  console.log('- Auto-delete unverified users after 10 minutes');
});
