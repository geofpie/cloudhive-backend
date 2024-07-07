require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs'); // For hashing passwords
const db = require('./config'); // Import MySQL connection from config.js
const JWT_SECRET = process.env.JWT_SECRET;
const jwt = require('jsonwebtoken'); // json web tokens
const cookieParser = require('cookie-parser');
const multer = require('multer'); // For handling file uploads
const AWS = require('aws-sdk'); // AWS SDK for S3 operations
const fs = require('fs'); // File system module

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

// Multer middleware for handling file uploads (profile picture)
const upload = multer({ dest: 'uploads/' });

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

// Endpoint for updating profile (including profile picture)
app.post('/api/onboard_profile_update', verifyToken, upload.single('profilePic'), (req, res) => {
    const userId = req.user.userId; // Extract user ID from JWT
    const { firstName, lastName, country } = req.body;
    const profilePicFile = req.file; // Multer uploads profilePic file data

    // Check if profilePicFile exists (optional: handle profile picture upload)
    if (profilePicFile) {
        // Read file data
        fs.readFile(profilePicFile.path, (err, data) => {
            if (err) {
                console.error('Error reading profile picture file:', err);
                return res.status(500).json({ error: 'Failed to read profile picture file' });
            }

            // Parameters for S3 upload
            const params = {
                Bucket: 'cloudhive-userdata', // Replace with your S3 bucket name
                Key: `${userId}/profilePic.jpg`, // File name in S3 bucket
                Body: data,
                ACL: 'private', // Set ACL to private to restrict access
            };

            // Upload to S3
            s3.upload(params, (s3Err, s3Data) => {
                if (s3Err) {
                    console.error('Error uploading to S3:', s3Err);
                    return res.status(500).json({ error: 'Failed to upload profile picture to S3' });
                }

                console.log('Profile picture uploaded successfully:', s3Data.Location);

                // Update user profile in database with profile picture URL
                db.query('UPDATE users SET first_name = ?, last_name = ?, country = ?, profile_pic_url = ? WHERE user_id = ?',
                    [firstName, lastName, country, s3Data.Location, userId],
                    (dbErr, dbResult) => {
                        if (dbErr) {
                            console.error('Error updating user profile in database:', dbErr);
                            return res.status(500).json({ error: 'Failed to update user profile' });
                        }

                        console.log('User profile updated successfully in database:', dbResult);

                        // Send success response
                        res.status(200).json({ message: 'User profile updated successfully' });
                    }
                );
            });
        });
    } else {
        // No profile picture uploaded
        // Update user profile in database without profile picture URL
        db.query('UPDATE users SET first_name = ?, last_name = ?, country = ? WHERE user_id = ?',
            [firstName, lastName, country, userId],
            (dbErr, dbResult) => {
                if (dbErr) {
                    console.error('Error updating user profile in database:', dbErr);
                    return res.status(500).json({ error: 'Failed to update user profile' });
                }

                console.log('User profile updated successfully in database:', dbResult);

                // Send success response
                res.status(200).json({ message: 'User profile updated successfully' });
            }
        );
    }
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


// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
