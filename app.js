require('dotenv').config();


const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccountKey.json');

const app = express();
app.use(cors());
app.use(express.json());

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const userSchema = new mongoose.Schema({
  fullname: String,
  email: { type: String, unique: true },
  passwordHash: String,
  provider: String
}, { collection: 'User' });

const User = mongoose.model('User', userSchema);

app.post('/signup', async (req, res) => {
  try {
    const { fullname, email, password } = req.body;
    if (!fullname || !email || !password) {
      return res.status(400).json({ error: 'Fullname, email, and password are required.' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = new User({ fullname, email, passwordHash, provider: 'local' });
    await newUser.save();
    res.status(201).json({ message: 'User created' });
  } catch (err) {
    if (err.code === 11000) {
      res.status(400).json({ error: 'Email already exists.' });
    } else {
      res.status(500).json({ error: 'Internal server error' });
    }
  }
});

app.post('/google-signin', async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) {
      return res.status(400).json({ error: 'ID token is required.' });
    }
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { name, email } = decodedToken;
    let user = await User.findOne({ email });
    if (!user) {
      user = new User({
        fullname: name,
        email,
        passwordHash: null,
        provider: 'google'
      });
      await user.save();
    } else if (user.provider !== 'google') {
      user.provider = 'google';
      await user.save();
    }
    res.status(200).json({ message: 'Google sign-in successful', user });
  } catch (err) {
    res.status(500).json({ error: 'Google sign-in failed' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'User not found.' });
    }
    if (user.provider !== 'local') {
      return res.status(400).json({ message: `This account uses ${user.provider} Sign-in. Please login with ${user.provider}.` });
    }
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid password.' });
    }
    res.status(200).json({
      message: 'Login successful',
      email: user.email,
      id: user._id
    });
  } catch (err) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

mongoose.connect(
  'mongodb+srv://adminser:adm1n12345@user.rnzf0bx.mongodb.net/?retryWrites=true&w=majority&appName=user',
  { useNewUrlParser: true, useUnifiedTopology: true }
).then(() => {
  app.listen(3000, () => console.log('Server running on port 3000'));
}).catch(err => {
  console.error('MongoDB connection error:', err);
});
