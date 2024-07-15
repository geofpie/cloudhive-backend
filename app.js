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
const crypto = require('crypto');
const path = require('path');
const dynamoDB = new AWS.DynamoDB.DocumentClient({ region: 'us-east-1' });

const app = express();
const port = 8080;

// Configure AWS SDK for S3
const s3 = new AWS.S3({
    region: 'us-east-1', 
    signatureVersion: 'v4'
});

const upload = multer({ storage: multer.memoryStorage() });

const TABLE_NAME = 'cloudhive-postdb';

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static('public'));
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

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
        return res.status(401).json({ redirect: '/' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ redirect: '/' });
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
    const userId = req.user.userId;

    // Log the user ID
    console.log(`Fetching information for user ID: ${userId}`);

    // Fetch user information from database
    db.query('SELECT first_name, last_name, profilepic_key, username, email FROM users WHERE user_id = ?', [userId], (err, results) => {
        if (err) {
            console.error('Error fetching user information:', err);
            return res.status(500).json({ error: 'Failed to fetch user information' });
        }

        if (results.length === 0) {
            console.log('User not found');
            return res.status(404).json({ error: 'User not found' });
        }

        const userInfo = results[0];

        // Log the fetched user information
        console.log('User information fetched:', userInfo);

        // Generate presigned URL for profile picture
        const profilePictureKey = userInfo.profilepic_key;
        if (profilePictureKey) {
            console.log(`Profile picture key found: ${profilePictureKey}`);
            const params = {
                Bucket: 'cloudhive-userdata',
                Key: profilePictureKey,
                Expires: 60 * 60 // 1 hour expiration
            };
            s3.getSignedUrl('getObject', params, (err, url) => {
                if (err) {
                    console.error('Error generating presigned URL:', err);
                    return res.status(500).json({ error: 'Failed to generate presigned URL' });
                }

                console.log(`Presigned URL generated: ${url}`);
                userInfo.profile_picture_url = url;
                res.status(200).json({ userInfo });
            });
        } else {
            console.log('No profile picture key found');
            res.status(200).json({ userInfo });
        }
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
    const profilePicKey = `profile-pics/${req.user.userId}-${req.user.username}-${randomString}.${extension}`;

    // Create S3 upload parameters
    const params = {
        Bucket: 'cloudhive-userdata', 
        Key: profilePicKey,
        Body: req.file.buffer,
        ContentType: req.file.mimetype,
        ACL: 'private' 
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
        db.query('UPDATE users SET profile_pic = ?, profilepic_key = ?, first_name = ?, last_name = ?, country = ? WHERE user_id = ?', 
            [profilePicUrl, profilePicKey, firstName, lastName, country, req.user.userId], 
            (err, result) => {
                if (err) {
                    console.error('Error updating user information in database:', err);
                    return res.status(500).json({ error: 'Failed to update user information' });
                }

                res.status(200).json({ message: 'Profile picture and user information updated successfully', profilePicUrl });
            });
    });
});

// Endpoint to fetch and render user profile page
app.get('/:username', verifyToken, (req, res) => {
    const username = req.params.username;
    console.log(`Fetching profile for username: ${username}`);

    // Fetch user information from database
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            console.error('Error fetching user information:', err);
            return res.status(500).send('Internal Server Error');
        }

        if (results.length === 0) {
            console.log(`User ${username} not found`);
            return res.status(404).send('User not found');
        }

        const userInfo = results[0];

        if (userInfo.profilepic_key) {
            const params = {
                Bucket: 'cloudhive-userdata',
                Key: userInfo.profilepic_key,
                Expires: 3600 // 1 hour expiration (in seconds)
            };
            s3.getSignedUrl('getObject', params, (err, url) => {
                if (err) {
                    console.error('Error generating presigned URL:', err);
                    return res.status(500).send('Internal Server Error');
                }

                userInfo.profile_picture_url = url;

                console.log(`Rendering profile page for ${username}`);
                res.render('profile', { user: userInfo, loggedInUser: req.user });
            });
        } else {
            // Render profile.html with user data
            console.log(`Rendering profile page for ${username}`);
            res.render('profile', { user: userInfo, loggedInUser: req.user });
        }
    });
});

app.post('/api/posts', (req, res) => {
    const { userId, content, imageUrl } = req.body;
    console.log('Received POST request to create a post');
    console.log('Request body:', req.body);

    // Validate inputs (userId should be fetched from req.user or req.session)
    if (!userId || !content) {
        return res.status(400).json({ message: 'userId and content are required' });
    }

    // Save the post to DynamoDB or your preferred database
    const postId = generatePostId(); // Implement your own postId generation function
    const createdAt = new Date().toISOString();

    const params = {
        TableName: 'cloudhive-postdb',
        Item: {
            postId,
            userId,
            content,
            imageUrl,
            createdAt
        }
    };

    dynamoDB.put(params, (err, data) => {
        if (err) {
            console.error('Error saving post:', err);
            return res.status(500).json({ message: 'Failed to save post' });
        }

        res.status(201).json({ postId });
    });
});

app.post('/api/create_post', verifyToken, upload.single('postImage'), (req, res) => {
    const { content } = req.body;
    const userId = req.user.userId.toString(); // Ensure userId is a string
    const username = req.user.username;

    let imageUrl = null;

    if (req.file) {
        const file = req.file;
        const fileExtension = file.mimetype.split('/')[1];
        const fileKey = `posts/${userId}-${crypto.randomBytes(6).toString('hex')}.${fileExtension}`;

        const uploadParams = {
            Bucket: 'cloudhive-userdata',
            Key: fileKey,
            Body: file.buffer,
            ContentType: file.mimetype,
            ACL: 'private'
        };

        s3.upload(uploadParams, (err, data) => {
            if (err) {
                console.error('Error uploading image:', err);
                return res.status(500).json({ error: 'Failed to upload image' });
            }

            imageUrl = data.Location;
            savePostToDynamoDB(userId, username, content, imageUrl, res);
        });
    } else {
        savePostToDynamoDB(userId, username, content, imageUrl, res);
    }
});

function savePostToDynamoDB(userId, username, content, imageUrl, res) {
    const postId = crypto.randomBytes(16).toString('hex');
    const timestamp = new Date().toISOString();

    const params = {
        TableName: 'cloudhive-postdb',
        Item: {
            postId: postId,
            userId: userId,
            username: username,
            content: content,
            imageUrl: imageUrl,
            timestamp: timestamp
        }
    };

    dynamoDB.put(params, (err, data) => {
        if (err) {
            console.error('Error saving post to DynamoDB:', err);
            return res.status(500).json({ error: 'Failed to save post' });
        }

        res.status(201).json({ message: 'Post created successfully' });
    });
}

function savePostToDynamoDB(userId, username, content, imageUrl, res) {
    const postId = crypto.randomBytes(16).toString('hex');
    const timestamp = new Date().toISOString();

    const params = {
        TableName: TABLE_NAME,
        Item: {
            postId: postId,
            userId: userId,
            username: username,
            content: content,
            imageUrl: imageUrl,
            timestamp: timestamp
        }
    };

    dynamoDB.put(params, (err, data) => {
        if (err) {
            console.error('Error saving post to DynamoDB:', err);
            return res.status(500).json({ error: 'Failed to save post' });
        }

        res.status(201).json({ message: 'Post created successfully' });
    });
}

// POST endpoint to fetch posts by username
app.post('/api/get_posts', (req, res) => {
    const { limit, lastEvaluatedKey, username } = req.body;

    console.log('Received request to fetch posts. Username:', username);

    // Check if username is provided
    if (!username) {
        console.error('Username is missing in request body.');
        return res.status(400).json({ error: 'Username is required.' });
    }

    // Define DynamoDB query parameters
    const params = {
        TableName: TABLE_NAME,
        Limit: limit,
        ExclusiveStartKey: lastEvaluatedKey,
        KeyConditionExpression: 'username = :user', // Adjust KeyConditionExpression as per your table schema
        ExpressionAttributeValues: {
            ':user': { S: username }  // Assuming username is a string (S)
        }
    };

    console.log('Query parameters:', params);

    // Perform DynamoDB query
    dynamoDB.query(params, (err, data) => {
        if (err) {
            console.error('Error fetching posts from DynamoDB:', err);
            return res.status(500).json({ error: 'Error fetching posts from DynamoDB' });
        }
        
        console.log('Query result:', data);

        res.json(data);
    });
});

app.get('/api/follow/:username', (req, res) => {
    const followerUsername = req.session.username;  // Assuming you store the logged-in username in the session
    const followedUsername = req.params.username;

    if (followerUsername === followedUsername) {
        return res.status(400).send('You cannot follow yourself');
    }

    // Get user IDs based on usernames
    const getUserIdsQuery = `
        SELECT user_id, username FROM users WHERE username IN (?, ?)
    `;

    connection.query(getUserIdsQuery, [followerUsername, followedUsername], (err, results) => {
        if (err) return res.status(500).send('Database error');

        const followerId = results.find(user => user.username === followerUsername).id;
        const followedId = results.find(user => user.username === followedUsername).id;

        // Insert follow request
        const insertFollowRequestQuery = `
            INSERT INTO follows (follower_id, followed_id, status)
            VALUES (?, ?, 'requested')
            ON DUPLICATE KEY UPDATE status = 'requested'
        `;

        connection.query(insertFollowRequestQuery, [followerId, followedId], (err, results) => {
            if (err) return res.status(500).send('Database error');
            res.send('Follow request sent');
        });
    });
});

app.get('/api/approve-follow/:username', (req, res) => {
    const requesteeUsername = req.session.username;  // Assuming you store the logged-in username in the session
    const requesterUsername = req.params.username;

    // Get user IDs based on usernames
    const getUserIdsQuery = `
        SELECT id, username FROM users WHERE username IN (?, ?)
    `;

    connection.query(getUserIdsQuery, [requesterUsername, requesteeUsername], (err, results) => {
        if (err) return res.status(500).send('Database error');

        const requesterId = results.find(user => user.username === requesterUsername).id;
        const requesteeId = results.find(user => user.username === requesteeUsername).id;

        // Update follow request status to 'following'
        const updateFollowRequestQuery = `
            UPDATE following_table
            SET status = 'following'
            WHERE follower_id = ? AND followed_id = ? AND status = 'requested'
        `;

        connection.query(updateFollowRequestQuery, [requesterId, requesteeId], (err, results) => {
            if (err) return res.status(500).send('Database error');
            res.send('Follow request approved');
        });
    });
});


// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
