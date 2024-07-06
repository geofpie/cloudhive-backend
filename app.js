const express = require('express');
const bodyParser = require('body-parser');
const db = require('./config'); // Import MySQL connection from config.js

const app = express();
const port = 8080; // Port for your application

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));

// Connect to MySQL
db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL database:', err.stack);
        return;
    }
    console.log('Connected to MySQL database');
    console.log('DB Host:', db.config.host);
    console.log('DB Database:', db.config.database);
    console.log('DB User:', db.config.user);
});

// Routes
app.get('/', (req, res) => {
    res.send('Hello, World!');
});

// Example route using database connection
app.get('/users', (req, res) => {
    db.query('SELECT * FROM users', (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database query failed' });
        }
        res.json(results);
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
