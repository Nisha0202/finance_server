const express = require('express');
const cors = require('cors');
const {ObjectId } = require('mongodb');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { MongoClient, ServerApiVersion } = require('mongodb');
dotenv.config();

const app = express();
const port = process.env.PORT || 5000;
const saltRounds = 10;

const uri = `mongodb+srv://${process.env.S3_BUCKET}:${process.env.SECRET_KEY}@cluster0.5cua0xk.mongodb.net/finance?retryWrites=true&w=majority`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});
app.use(cors());
app.use(express.json());


let userCollection;



async function run() {

  try {
      
    const database = client.db('finance');
    userCollection = database.collection('userinfo');



  // Registration Endpoint
  app.post('/api/register', async (req, res) => {
    const { name, pin, mobile, email, role } = req.body;

    try {
      // Check if a user or agent with the same email or mobile number already exists
      const existingUser = await userCollection.findOne({ $or: [{ email }, { mobile }] });
      if (existingUser) {
        return res.status(400).send({ message: 'User or agent with this email or mobile number already exists. Please login.' });
      }

      const hashedPin = await bcrypt.hash(pin, saltRounds);
      const newUser = {
        name,
        pin: hashedPin,
        mobile,
        email,
        role,
        status: 'pending',
        balance: 0,
      };

      await userCollection.insertOne(newUser);
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
      const user = await userCollection.findOne({ $or: [{ email: emailOrMobile }, { mobile: emailOrMobile }] });
      if (!user) {
        return res.status(404).send({ message: 'User not found. Please check your credentials.' });
      }

      // Verify PIN
      const isMatch = await bcrypt.compare(pin, user.pin);
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


  // Fetch user data by ID
  app.get('/api/user/:id', async (req, res) => {
    const userId = req.params.id;

    try {
      const user = await userCollection.findOne({ _id: new ObjectId(userId) });
      if (!user) {
        return res.status(404).send({ message: 'User not found' });
      }
      res.status(200).json(user);
    } catch (error) {
      console.error('Error fetching user data:', error);
      res.status(500).send({ message: 'Error fetching user data' });
    }
  });



  
      // Send a ping to confirm a successful connection
      console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
      // Ensures that the client will close when you finish/error
      // await client.close();
  }

}

run().catch(console.dir);

app.get('/', (req, res) =>{
  res.send('server running')
})

app.listen(port, ()=>{
  console.log(`Port:${port}`)
})


