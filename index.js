const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { MongoClient, ObjectId } = require('mongodb');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser')
const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors({
    origin: ['http://localhost:5173', 'https://frost-fit.vercel.app'],
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

function isAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    // console.log(authHeader);
    if (!authHeader) {
        return res.status(401).json({ message: 'No token provided' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.id;
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid token' });
    }
}



// MongoDB Connection URL
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });

async function run() {
    try {
        // Connect to MongoDB
        await client.connect();
        console.log("Connected to MongoDB");

        const db = client.db('frostfit');
        const collection = db.collection('users');
        const clothesCollection = db.collection('clothes');

        function generateAccessToken(user) {
            return jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: process.env.EXPIRES_IN });
        }

        function generateRefreshToken(user) {
            const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN });
            return refreshToken;
        }

        // User Registration
        app.post('/api/v1/register', async (req, res) => {
            const { name, email, password } = req.body;

            // Check if email already exists
            const existingUser = await collection.findOne({ email });
            if (existingUser) {
                return res.status(400).json({
                    success: false,
                    message: 'User already exists'
                });
            }

            // Hash the password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert user into the database
            const result = await collection.insertOne({ name, email, password: hashedPassword, role: 'user', status: 'active' });
            const user = { _id: result.insertedId };
            const token = generateAccessToken(user);
            const refreshToken = generateRefreshToken(user);


            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'Strict',
                maxAge: 6 * 30 * 24 * 60 * 60 * 1000 // 6 months
            });

            res.status(201).json({
                success: true,
                message: 'User registered successfully',
                token,
                refreshToken
            });
        });

        // User Login
        app.post('/api/v1/login', async (req, res) => {
            const { email, password } = req.body;

            // Find user by email
            const user = await collection.findOne({ email });
            if (!user) {
                return res.status(401).json({ message: 'Invalid email or password' });
            }

            // Compare hashed password
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                return res.status(401).json({ message: 'Invalid email or password' });
            }

            // Generate JWT tokens
            const token = generateAccessToken(user);
            const refreshToken = generateRefreshToken(user);

            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'Strict',
                maxAge: 6 * 30 * 24 * 60 * 60 * 1000
            });

            res.json({
                success: true,
                message: 'Login successful',
                token,
                refreshToken,
                user: { ...user, password: null },
            });
        });


        app.post('/api/v1/refresh', async (req, res) => {
            const { refreshToken } = req.cookies;
            if (!refreshToken) {
                return res.status(401).json({ message: 'No Refresh token provided' });
            }
            try {
                const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
                const user = await collection.findOne({ _id: new ObjectId(decoded.id) });
                if (!user) {
                    return res.status(401).json({ message: 'Invalid token' });
                }
                const newAccessToken = generateAccessToken(user);
                const newRefreshToken = generateRefreshToken(user);

                res.cookie('refreshToken', refreshToken, {
                    httpOnly: true,
                    secure: true,
                    sameSite: 'Strict',
                    maxAge: 6 * 30 * 24 * 60 * 60 * 1000
                });
                res.json({
                    success: true,
                    accessToken: newAccessToken,
                    refreshToken: newRefreshToken
                });
            } catch (error) {
                return res.status(401).json({ message: 'Invalid token' });
            }
        });

      
        // get all users
        app.get('/api/v1/users', isAuth, async (req, res) => {

            const users = await collection.find({}).toArray();
            res.json({
                success: true,
                message: 'Users retrieved successfully',
                users,
            });
        })
        // get single user

        app.get('/api/v1/user', isAuth, async (req, res) => {
            try {
                const user = await collection.findOne({ _id: new ObjectId(req.userId) });

                if (!user) {
                    return res.status(404).json({
                        success: false,
                        message: 'User not found',
                    });
                }

                res.json({
                    success: true,
                    message: 'User retrieved successfully',
                    user: { ...user, password: null },
                });
            } catch (error) {
                res.status(500).json({
                    success: false,
                    message: 'An error occurred while retrieving the user',
                });
            }
        });


        // update user status

        app.patch('/api/v1/user/:id', isAuth, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            console.log({ query, role: req.body.role });
            try {
                const result = await collection.updateOne(query, { $set: { role: req.body.role } });

                res.status(200).json({
                    success: true,
                    message: "Role Updated successfully",
                    result
                })
            } catch (error) {
                console.log(error);
                res.status(500).json({
                    success: false,
                    message: "something went wrong",
                    error
                })
            }

        })


        // Add cloth
        app.post('/api/v1/cloth', isAuth, async (req, res) => {
            const { category, title, sizes, description, img, amount } = req.body;
            try {
                const result = await clothesCollection.insertOne({ category, title, sizes, description, img, amount, addedBy: req.userId });
                res.json({
                    success: true,
                    message: 'Cloth added successfully',
                    result,
                });

            } catch (error) {
                console.log(error);
                res.status(500).json({
                    success: false,
                    message: 'Failed to add cloth',
                    error
                });
            }
        })


        // get all clothes
        app.get('/api/v1/clothes', async (req, res) => {
            try {

                const clothes = await clothesCollection.find().toArray();
                res.json({
                    success: true,
                    message: 'Clothes retrieved successfully',
                    clothes,
                });
            } catch (error) {
                console.log(error);
                res.status(500).json({
                    success: false,
                    message: 'Failed to retrieve clothes',
                    error
                });
            }
        })

        // get single cloth
        app.get('/api/v1/cloth/:id', async (req, res) => {
            const id = req.params.id;
            try {
                const cloth = await clothesCollection.findOne({ _id: new ObjectId(id) });
                res.json({
                    success: true,
                    message: 'Cloth retrieved successfully',
                    cloth,
                });
            } catch (error) {
                console.log(error);
                res.status(500).json({
                    success: false,
                    message: 'Failed to retrieve cloth',
                    error
                });
            }
        })


        // update cloth

        app.patch('/api/v1/cloth/:id', isAuth, async (req, res) => {
            const id = req.params.id;
            const { category, title, sizes, description, img } = req.body;
            try {
                const result = await clothesCollection.updateOne({ _id: new ObjectId(id) }, { $set: { category, title, sizes, description, img } });
                res.json({
                    success: true,
                    message: 'Cloth updated successfully',
                    result,
                });
            } catch (error) {
                console.log(error);
                res.status(500).json({
                    success: false,
                    message: 'Failed to update cloth',
                    error
                });
            }
        })


        // delete cloth
        app.delete('/api/v1/cloth/:id', isAuth, async (req, res) => {
            const id = req.params.id;
            console.log(id)
            try {
                const result = await clothesCollection.deleteOne({ _id: new ObjectId(id) });
                res.json({
                    success: true,
                    message: 'Cloth deleted successfully',
                    result,
                });
            } catch (error) {
                console.log(error);
                res.status(500).json({
                    success: false,
                    message: 'Failed to delete cloth',
                    error
                });
            }
        })

        // post donation
        app.post('/api/v1/donate', isAuth, async (req, res) => {
            const { id, amount } = req.body;
            const query = { _id: new ObjectId(id) };

            try {
                const item = await clothesCollection.findOne(query);
                if (!item) {
                    return res.status(404).json({
                        success: false,
                        message: 'Item not found'
                    });
                }

                // Update operation
                let update = { $inc: { amount: -amount }, $set: { donated: true, donatedBy: req.userId } };

                // Check if donationAmount already exists
                if (item.donationAmount) {
                    update.$inc.donationAmount = amount;
                } else {
                    update.$set.donationAmount = amount;
                }

                const result = await clothesCollection.updateOne(
                    query,
                    update
                );

                res.status(200).json({
                    success: true,
                    message: 'Donation successful',
                    result
                });
            } catch (error) {
                console.error('Error processing donation:', error);
                res.status(500).json({ success: false, message: 'Error processing donation' });
            }
        });



        app.get('/api/v1/statistics', isAuth, async (req, res) => {
            try {
                const totalUsers = await collection.countDocuments();
                const clothes = await clothesCollection.find().toArray();
                const donationItems = await clothesCollection.find({ donated: true }).toArray();
                const totalDonations = donationItems.reduce((total, item) => total + item.donationAmount, 0);
                const totalClothes = clothes.reduce((total, item) => total + item.amount, 0);

                res.status(200).json({
                    success: true,
                    message: 'Statistics retrieved successfully',
                    totalUsers,
                    totalDonations,
                    totalClothes
                });
            } catch (error) {
                console.log(error);
                res.status(500).json({
                    success: false,
                    message: 'Failed to retrieve statistics',
                    error: error.message
                });
            }
        });







        // Start the server
        app.listen(port, () => {
            console.log(`Server is running on http://localhost:${port}`);
        });

    } finally {
    }
}

run().catch(console.dir);

// Test route
app.get('/', (req, res) => {
    const serverStatus = {
        message: 'Server is running smoothly',
        timestamp: new Date()
    };
    res.json(serverStatus);
});
