const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs'); // For hashing passwords
const db = require('./config'); // Import MySQL connection from config.js
const net = require('net'); // For TCP socket operations

const app = express();
const port = 8080;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Function to check if port is open on a given IP
function checkPort(ip, port) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(2000); // Timeout in milliseconds

        socket.on('connect', () => {
            console.log(`Port ${port} is open on ${ip}`);
            socket.destroy(); // Close the connection
            resolve(true);
        });

        socket.on('timeout', () => {
            console.log(`Timeout while attempting to connect to port ${port} on ${ip}`);
            socket.destroy(); // Close the connection
            resolve(false);
        });

        socket.on('error', (err) => {
            console.error(`Error connecting to port ${port} on ${ip}: ${err.message}`);
            resolve(false);
        });

        socket.connect(port, ip);
    });
}

// Check if port 8080 is open on the web server (10.0.8.34)
const webServerIP = '10.0.8.34';
const portToCheck = 8080;
checkPort(webServerIP, portToCheck)
    .then((isOpen) => {
        if (isOpen) {
            console.log(`Port ${portToCheck} is open on ${webServerIP}`);
            startServer(); // Start the Express server if port is open
        } else {
            console.log(`Port ${portToCheck} is closed or unreachable on ${webServerIP}`);
        }
    })
    .catch((err) => {
        console.error('Error checking port:', err);
    });

// Function to start the Express server
function startServer() {
    // Connect to MySQL
    db.connect((err) => {
        if (err) {
            console.error('Error connecting to MySQL database:', err);
            throw err;
        }
        console.log('Connected to MySQL database');
    });

    // Register endpoint
    app.post('/register', (req, res) => {
        const { username, email, password } = req.body;

        // Hash the password
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                console.error('Error hashing password:', err);
                return res.status(500).json({ error: 'Password hashing failed' });
            }

            // Save user to database
            const newUser = { username, email, password: hashedPassword };
            db.query('INSERT INTO users SET ?', newUser, (err, result) => {
                if (err) {
                    console.error('Error inserting user into database:', err);
                    return res.status(500).json({ error: 'Failed to register user' });
                }
                console.log('User registered successfully:', result);
                res.status(200).json({ message: 'User registered successfully' });
            });
        });
    });

    // Start server
    app.listen(port, () => {
        console.log(`Server running on port ${port}`);
    });
}
