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

const app = express();
const port = 8080;

// Configure AWS SDK for S3
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// Connect to MySQL
db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL database:', err);
        throw err;
    }
    console.log('Connected to MySQL database');
});

// Register endpoint
app.post('/api/register', (req, res) => {
    const { username, email, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], (err, results) => {
        if (err) {
            console.error('Error checking user existence:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length > 0) {
            return res.status(409).json({ error: 'Username or email already exists' });
        }

        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                console.error('Error hashing password:', err);
                return res.status(500).json({ error: 'Password hashing failed' });
            }

            const newUser = { username, email, password_hash: hashedPassword };
            db.query('INSERT INTO users SET ?', newUser, (err, result) => {
                if (err) {
                    console.error('Error inserting user into database:', err);
                    return res.status(500).json({ error: 'Failed to register user. Database error: ' + err.message });
                }

                const userId = result.insertId;
                const token = jwt.sign({ userId, username }, JWT_SECRET, { expiresIn: '1h' });

                // Log token generation
                console.log('JWT Token Generated:', token);

                // Send the token as part of the response
                res.cookie('token', token, { httpOnly: true, secure: false }); // change this to true in prod

                console.log('User registered successfully:', result);
                
                // Notify user registration is successful
                res.status(200).json({ message: 'User registered successfully', token });
            });
        });
    });
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

// New login and fetch user info endpoint
app.post('/api/login_redirect', (req, res) => {
    const { identifier, password } = req.body; // Use 'identifier' to accept either username or email

    // Fetch user from database based on username or email
    db.query('SELECT * FROM users WHERE username = ? OR email = ?', [identifier, identifier], (err, results) => {
        if (err) {
            console.error('Error retrieving user:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(401).json({ error: 'Invalid username or email or password' });
        }

        const user = results[0];

        // Compare hashed password with provided password
        bcrypt.compare(password, user.password_hash, (bcryptErr, bcryptRes) => {
            if (bcryptErr || !bcryptRes) {
                return res.status(401).json({ error: 'Invalid username or email or password' });
            }

            // Generate JWT token
            const token = jwt.sign({ userId: user.user_id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

            // Log token generation
            console.log('JWT Token Generated:', token);

            // Send token in a cookie
            res.cookie('token', token, { httpOnly: true, secure: false }); // Change to secure: true in production

            // Fetch user information
            db.query('SELECT username, email, first_name, last_name, country FROM users WHERE user_id = ?', [user.user_id], (err, results) => {
                if (err) {
                    console.error('Error fetching user information:', err);
                    return res.status(500).json({ error: 'Failed to fetch user information' });
                }

                if (results.length === 0) {
                    return res.status(404).json({ error: 'User not found' });
                }

                const userInfo = results[0];

                console.log('User information retrieved successfully:', userInfo);

                // Check if required fields are empty
                if (!userInfo.first_name || !userInfo.last_name || !userInfo.country) {
                    return res.status(302).json({ redirect: '/onboarding' });
                }

                res.status(200).json({ message: 'Login successful', token, userInfo });
            });
        });
    });
});

// Endpoint to fetch logged-in user info
app.get('/api/get_user_info', verifyToken, (req, res) => {
    const userId = req.user.userId; // Extract user ID from JWT

    // Fetch user information from database
    db.query('SELECT username, email FROM users WHERE user_id = ?', [userId], (err, results) => {
        if (err) {
            console.error('Error fetching user information:', err);
            return res.status(500).json({ error: 'Failed to fetch user information' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const userInfo = results[0];
        res.status(200).json({ userInfo });
    });
});

app.post('/api/onboard_profile_update', verifyToken, upload.single('profilePic'), (req, res) => {
    if (!req.file) {
        console.log('No file uploaded');
        return res.status(400).json({ error: 'No file uploaded' });
    }

    // Log the received file details
    console.log('File received:', req.file);

    // Determine the file extension
    const mimeType = req.file.mimetype;
    let extension = '';
    switch (mimeType) {
        case 'image/jpeg':
            extension = 'jpg';
            break;
        case 'image/png':
            extension = 'png';
            break;
        case 'image/gif':
            extension = 'gif';
            break;
        default:
            return res.status(400).json({ error: 'Unsupported file type' });
    }

    const randomString = crypto.randomBytes(6).toString('hex');

    // Create S3 upload parameters
    const params = {
        Bucket: 'cloudhive-userdata', 
        Key: `profile-pics/${req.user.userId}-${req.user.username}-${randomString}.${extension}`, // User ID and username as the filename
        Body: req.file.buffer,
        ContentType: req.file.mimetype,
        ACL: 'private' // Ensure the file is private
    };

    // Log the S3 upload parameters
    console.log('S3 upload parameters:', params);

    // Upload the file to S3
    s3.upload(params, (err, data) => {
        if (err) {
            console.error('Error uploading file to S3:', err);
            return res.status(500).json({ error: 'Failed to upload file' });
        }

        console.log('File uploaded successfully:', data);

        // Update the user's profile picture URL and additional fields in the database
        const profilePicUrl = data.Location;
        const firstName = req.body['first-name'];
        const lastName = req.body['last-name'];
        const country = req.body.country;

        // Update user information in the database
        db.query('UPDATE users SET profile_pic = ?, first_name = ?, last_name = ?, country = ? WHERE user_id = ?', 
            [profilePicUrl, firstName, lastName, country, req.user.userId], 
            (err, result) => {
                if (err) {
                    console.error('Error updating user information in database:', err);
                    return res.status(500).json({ error: 'Failed to update user information' });
                }

                res.status(200).json({ message: 'Profile picture and user information updated successfully', profilePicUrl });
            });
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
