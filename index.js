const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;
const saltRounds = 10;

const uri = `mongodb+srv://${process.env.S3_BUCKET}:${process.env.SECRET_KEY}@cluster0.5cua0xk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

mongoose.connect(uri)
  .then(() => console.log('Successfully connected to MongoDB'))
  .catch((err) => console.error('Error connecting to MongoDB:', err));

app.use(cors());
app.use(express.json());

// Define User schema and model using Mongoose
const userSchema = new mongoose.Schema({
  name: String,
  pin: String, // hashed PIN will be stored here
  mobile: String,
  email: String,
  role: String,
  status: String,
  balance: Number,
});

const User = mongoose.model('User', userSchema);

// Registration Endpoint
app.post('/api/register', async (req, res) => {
  const { name, pin, mobile, email, role } = req.body;

  try {
    // Check if a user or agent with the same email or mobile number already exists
    const existingUser = await User.findOne({ $or: [{ email }, { mobile }] });
    if (existingUser) {
      return res.status(400).send({ message: 'User or agent with this email or mobile number already exists. Please login.' });
    }

    const hashedPin = await bcrypt.hash(pin, saltRounds);
    const newUser = new User({
      name,
      pin: hashedPin,
      mobile,
      email,
      role,
      status: 'pending',
      balance: 0,
    });

    await newUser.save();
    res.status(201).send({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).send({ message: 'Error registering user' });
  }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
  const { emailOrMobile, pin } = req.body;

  try {
    // Find user by email or mobile number
    const user = await User.findOne({ $or: [{ email: emailOrMobile }, { mobile: emailOrMobile }] });
    if (!user) {
      return res.status(404).send({ message: 'User not found. Please check your credentials.' });
    }

    // Verify PIN
    const isMatch = bcrypt.compare(pin, user.pin);
    if (!isMatch) {
      return res.status(401).send({ message: 'Invalid PIN. Please try again.' });
    }

    // Determine role based on email
    let role = 'user';
    if (user.email === 'admin@gmail.com') {
      role = 'admin';
    } else if (user.role === 'agent') {
      role = 'agent';
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' } // Token expires in 1 hour
    );

    res.status(200).json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send({ message: 'Login failed. Please check your credentials.' });
  }
});

app.get('/', (req, res) => {
  res.send('Server running');
});

app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
