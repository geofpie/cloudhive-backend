require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs'); // For hashing passwords
const db = require('./config'); // Import MySQL connection from config.js
const JWT_SECRET = process.env.JWT_SECRET;
const jwt = require('jsonwebtoken'); // json web tokens
console.log('JWT_SECRET:', process.env.JWT_SECRET); // remove in prod

const app = express();
const port = 8080;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

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
                    return res.status(500).json({ error: 'Failed to register user' });
                }

                const userId = result.insertId;
                const token = jwt.sign({ userId, username }, JWT_SECRET, { expiresIn: '1h' });
                res.cookie('token', token, { httpOnly: true, secure: false }); // change this to true in prod

                console.log('User registered successfully:', result);
                res.status(200).json({ message: 'User registered successfully' });
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
        next();
    });
};

// Onboarding endpoint
app.post('/api/onboard', verifyToken, (req, res) => {
    const { firstName, lastName, profilePic } = req.body;
    const userId = req.user.userId;

    const updateUser = { first_name: firstName, last_name: lastName, profile_pic: profilePic };
    db.query('UPDATE users SET ? WHERE id = ?', [updateUser, userId], (err, result) => {
        if (err) {
            console.error('Error updating user info:', err);
            return res.status(500).json({ error: 'Failed to update user info' });
        }
        console.log('User onboarded successfully:', result);
        res.status(200).json({ message: 'User onboarded successfully' });
    });
});


// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
