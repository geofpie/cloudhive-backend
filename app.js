const express = require('express');
const bodyParser = require('body-parser');
const db = require('./config'); // Import database connection from config.js

const app = express();
const port = 8080; // Port for your application

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));

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