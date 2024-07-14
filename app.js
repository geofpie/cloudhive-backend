// cloudhive Backend
// for EC2, built with nodejs and <3
// July 2024

// Import Modules 
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs'); // For hashing passwords
const db = require('./config'); // Import MySQL connection from config.js
const JWT_SECRET = process.env.JWT_SECRET;
const jwt = require('jsonwebtoken'); // json web tokens
const cookieParser = require('cookie-parser');
const AWS = require('aws-sdk'); // AWS SDK for S3 operations
const fs = require('fs'); // File system module
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });
const crypto = require('crypto');
const path = require('path');

const app = express();
const port = 8080;

// Configure AWS SDK for S3
const s3 = new AWS.S3({
    region: 'us-east-1', 
    signatureVersion: 'v4'
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static('public')); // Serve static files

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Connect to MySQL
db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL database:', err);
        throw err;
    }
    console.log('Connected to MySQL database');
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        req.user = decoded; // Attach the decoded token to the request object

        // Log user information
        console.log('User logged in:', req.user);

        next();
    });
};

// Endpoint to fetch and render user profile page
app.get('/:username', verifyToken, (req, res) => {
    const username = req.params.username;

    // Fetch user information from database
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            console.error('Error fetching user information:', err);
            return res.status(500).send('Internal Server Error');
        }

        if (results.length === 0) {
            return res.status(404).send('User not found');
        }

        const userInfo = results[0];

        // Generate presigned URL for profile picture if exists
        const profilePictureKey = userInfo.profilepic_key;
        if (profilePictureKey) {
            const params = {
                Bucket: 'cloudhive-userdata',
                Key: profilePictureKey,
                Expires: 60 * 60 // 1 hour expiration
            };
            s3.getSignedUrl('getObject', params, (err, url) => {
                if (err) {
                    console.error('Error generating presigned URL:', err);
                    return res.status(500).send('Internal Server Error');
                }

                userInfo.profile_picture_url = url;

                // Render profile.ejs with user data
                res.render('profile', { user: userInfo });
            });
        } else {
            // Render profile.ejs with user data
            res.render('profile', { user: userInfo });
        }
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
