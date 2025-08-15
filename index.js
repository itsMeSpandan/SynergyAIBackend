// index.js
require('dotenv').config(); // Load environment variables

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const admin = require('firebase-admin');

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Firebase Admin using environment variables
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  }),
});

// --- Mongoose User Schema ---
const userSchema = new mongoose.Schema({
  fullname: String,
  email: { type: String, unique: true },
  passwordHash: String,
  provider: String,
}, { collection: 'User' });

const User = mongoose.model('User', userSchema);

// --- Root Route ---
app.get('/', (req, res) => {
  res.send('Backend is running! 🚀');
});

// --- Local Signup ---
app.post('/signup', async (req, res) => {
  try {
    const { fullname, email, password } = req.body;
    if (!fullname || !email || !password)
      return res.status(400).json({ error: 'Fullname, email, and password are required.' });

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = new User({ fullname, email, passwordHash, provider: 'local' });
    await newUser.save();

    res.status(201).json({ message: 'User created' });
  } catch (err) {
    if (err.code === 11000) res.status(400).json({ error: 'Email already exists.' });
    else res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Google Sign-In ---
app.post('/google-signin', async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ error: 'ID token is required.' });

    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { name, email } = decodedToken;

    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ fullname: name, email, passwordHash: null, provider: 'google' });
      await user.save();
    } else if (user.provider !== 'google') {
      user.provider = 'google';
      await user.save();
    }

    res.status(200).json({ message: 'Google sign-in successful', user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Google sign-in failed' });
  }
});

// --- Local Login ---
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password are required.' });

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'User not found.' });

    if (user.provider !== 'local')
      return res.status(400).json({ message: `This account uses ${user.provider} Sign-in. Please login with ${user.provider}.` });

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) return res.status(401).json({ message: 'Invalid password.' });

    res.status(200).json({ message: 'Login successful', email: user.email, id: user._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// --- Connect to MongoDB and Start Server ---
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    const port = process.env.PORT || 3000;
    app.listen(port, () => console.log(`Server running on port ${port}`));
  })
  .catch(err => console.error('MongoDB connection error:', err));
