// server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Connect to MongoDB with improved options
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/satellite-health-monitor', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
})
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  mfaEnabled: { type: Boolean, default: false },
  mfaSecret: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Auth middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization').replace('Bearer ', '');
    console.log('Authenticating with token:', token ? 'Token provided' : 'No token');
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    console.log('Token decoded, user ID:', decoded.userId);
    
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      console.log('User not found with ID:', decoded.userId);
      throw new Error();
    }
    
    console.log('User authenticated:', user.username);
    req.token = token;
    req.user = user;
    next();
  } catch (error) {
    console.error('Authentication error:', error.message || 'Unknown error');
    res.status(401).send({ error: 'Please authenticate' });
  }
};

// Register a new user
app.post('/api/users/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    console.log('Registration attempt for user:', username);
    
    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      console.log('User already exists:', username);
      return res.status(400).json({ error: 'User already exists' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create new user
    const user = new User({
      username,
      email,
      password: hashedPassword
    });
    
    await user.save();
    console.log('User registered successfully:', username);
    
    // Generate JWT
    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET || 'your_jwt_secret', 
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        mfaEnabled: user.mfaEnabled
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login user
app.post('/api/users/login', async (req, res) => {
  try {
    const { username, password, mfaToken } = req.body;
    console.log('Login attempt for user:', username);
    
    // Find user by username
    const user = await User.findOne({ username });
    if (!user) {
      console.log('User not found:', username);
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('Invalid password for user:', username);
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    console.log('Password matched for user:', username);
    console.log('MFA enabled:', user.mfaEnabled);
    
    // Check MFA if enabled
    if (user.mfaEnabled) {
      if (!mfaToken) {
        console.log('MFA required for user:', username);
        return res.status(200).json({
          requiresMfa: true,
          message: 'MFA token required',
          userId: user._id
        });
      }
      
      // Verify MFA token with wider window
      const verified = speakeasy.totp.verify({
        secret: user.mfaSecret,
        encoding: 'base32',
        token: mfaToken,
        window: 6  // Allow 3 minutes before and after (6 30-second periods)
      });
      
      if (!verified) {
        console.log('Invalid MFA token for user:', username);
        return res.status(400).json({ error: 'Invalid MFA token' });
      }
      
      console.log('MFA token verified for user:', username);
    }
    
    // Generate JWT
    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET || 'your_jwt_secret', 
      { expiresIn: '7d' }
    );
    
    console.log('Login successful for user:', username);
    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        mfaEnabled: user.mfaEnabled
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Setup MFA
app.post('/api/users/mfa/setup', auth, async (req, res) => {
  try {
    console.log('MFA setup requested for user:', req.user.username);
    
    // Generate new secret with better naming
    const secret = speakeasy.generateSecret({
      name: encodeURIComponent(`Satellite Monitor (${req.user.username})`),
      issuer: 'Satellite Health System'  // Add an issuer for better app recognition
    });
    
    console.log('Generated MFA secret:', secret.base32);
    
    // Save secret to user
    req.user.mfaSecret = secret.base32;
    await req.user.save();
    console.log('MFA secret saved to user profile');
    
    // Generate QR code
    QRCode.toDataURL(secret.otpauth_url, (err, dataUrl) => {
      if (err) {
        console.error('QR code generation error:', err);
        return res.status(500).json({ error: 'Error generating QR code' });
      }
      
      console.log('QR code generated successfully');
      res.json({
        secret: secret.base32,
        qrCode: dataUrl
      });
    });
  } catch (error) {
    console.error('MFA setup error:', error);
    res.status(500).json({ error: 'Server error during MFA setup' });
  }
});

// Enable MFA
app.post('/api/users/mfa/enable', auth, async (req, res) => {
  try {
    const { token } = req.body;
    console.log('MFA enable requested for user:', req.user.username);
    console.log('User secret:', req.user.mfaSecret);
    console.log('Token provided:', token);
    
    // Log current server time
    const currentTime = Math.floor(Date.now() / 1000);
    console.log('Current server time (seconds):', currentTime);
    
    // Verify token with wider window
    const verified = speakeasy.totp.verify({
      secret: req.user.mfaSecret,
      encoding: 'base32',
      token,
      window: 6  // Allow 3 minutes before and after
    });
    
    console.log('Verification result:', verified);
    
    if (!verified) {
      console.log('Invalid token for MFA enable:', token);
      return res.status(400).json({ error: 'Invalid token' });
    }
    
    // Enable MFA
    req.user.mfaEnabled = true;
    await req.user.save();
    console.log('MFA enabled successfully for user:', req.user.username);
    
    res.json({ message: 'MFA enabled successfully' });
  } catch (error) {
    console.error('MFA enable error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify MFA token (for second step of login)
app.post('/api/users/mfa/verify', async (req, res) => {
  try {
    const { userId, token } = req.body;
    console.log('MFA verification for user ID:', userId);
    console.log('Token provided:', token);
    
    // Find user
    const user = await User.findById(userId);
    if (!user) {
      console.log('User not found for MFA verify:', userId);
      return res.status(404).json({ error: 'User not found' });
    }
    
    console.log('User found, MFA secret exists:', !!user.mfaSecret);
    
    // Log current server time
    const currentTime = Math.floor(Date.now() / 1000);
    console.log('Current server time (seconds):', currentTime);
    
    // Generate expected token for debugging
    const expectedToken = speakeasy.totp({
      secret: user.mfaSecret,
      encoding: 'base32'
    });
    console.log('Expected token (for debugging):', expectedToken);
    
    // Verify token with wider window
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token,
      window: 6  // Allow 3 minutes before and after
    });
    
    console.log('Verification result:', verified);
    
    if (!verified) {
      console.log('Invalid MFA token:', token);
      return res.status(400).json({ error: 'Invalid token' });
    }
    
    console.log('MFA token verified successfully');
    
    // Generate JWT
    const jwtToken = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET || 'your_jwt_secret', 
      { expiresIn: '7d' }
    );
    
    res.json({
      token: jwtToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        mfaEnabled: user.mfaEnabled
      }
    });
  } catch (error) {
    console.error('MFA verify error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Debug endpoint to check current token (only for development)
if (process.env.NODE_ENV !== 'production') {
  app.get('/api/debug/current-token/:userId', async (req, res) => {
    try {
      const user = await User.findById(req.params.userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      const token = speakeasy.totp({
        secret: user.mfaSecret,
        encoding: 'base32'
      });
      
      res.json({ 
        currentToken: token,
        secret: user.mfaSecret,
        serverTime: Math.floor(Date.now() / 1000)
      });
    } catch (error) {
      res.status(500).json({ error: 'Server error' });
    }
  });
}

// Get user profile
app.get('/api/users/me', auth, (req, res) => {
  console.log('User profile requested for:', req.user.username);
  res.json({
    id: req.user._id,
    username: req.user.username,
    email: req.user.email,
    role: req.user.role,
    mfaEnabled: req.user.mfaEnabled
  });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));