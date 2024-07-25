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
const lambda = new AWS.Lambda({region: 'us-east-1'});

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

app.get('/api/healthcheck', (req, res) => {
    res.status(200).json({ message: 'OK' });
});

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
                const token = jwt.sign({ userId, username, email }, JWT_SECRET, { expiresIn: '1h' });

                // Log token generation
                console.log('JWT Token Generated:', token);

                // Send the token as part of the response
                res.cookie('token', token, { httpOnly: true, secure: true });

                console.log('User registered successfully:', result);

                // Prepare the payload for Lambda
                const payload = {
                    body: JSON.stringify({ email })
                };

                // Invoke Lambda function to subscribe user to SNS topic for cloudhive 
                const params = {
                    FunctionName: 'arn:aws:lambda:us-east-1:576047115698:function:cloudhiveSubscribeUser', 
                    InvocationType: 'Event', // Asynchronous invocation
                    Payload: JSON.stringify(payload) 
                };

                lambda.invoke(params, (lambdaErr, data) => {
                    if (lambdaErr) {
                        console.error('Error invoking Lambda function:', lambdaErr);
                    } else {
                        console.log('Lambda function invoked successfully:', data);
                    }
                });

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
            const token = jwt.sign({ userId: user.user_id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

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
        console.log(req.user.email);

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

                // Prepare payload for Lambda
                const payload = {
                    body: JSON.stringify({
                        email: req.user.email, // Assuming you have the email in req.user
                        username: req.user.username
                    })
                };

                // Invoke Lambda function to send a welcome email
                const lambdaParams = {
                    FunctionName: 'arn:aws:lambda:us-east-1:576047115698:function:cloudhiveWelcomeEmail', 
                    InvocationType: 'Event', // Asynchronous invocation
                    Payload: JSON.stringify(payload)
                };

                lambda.invoke(lambdaParams, (lambdaErr, data) => {
                    if (lambdaErr) {
                        console.error('Error invoking Lambda function:', lambdaErr);
                        console.log(req.user.email);
                        console.log(payload);
                    } else {
                        console.log('Lambda function invoked successfully:', data);
                        console.log(payload);
                    }
                });

                // Notify user registration is successful
                res.status(200).json({ message: 'Profile picture and user information updated successfully', profilePicUrl });
            });
    });
});


app.get('/:username', verifyToken, (req, res) => {
    const username = req.params.username;
    console.log(`Fetching profile for username: ${username}`);

    // Fetch user information from MySQL database
    const userQuery = 'SELECT * FROM users WHERE username = ?';
    db.query(userQuery, [username], (err, userResults) => {
        if (err) {
            console.error('Error fetching user information:', err);
            return res.status(500).send('Internal Server Error');
        }

        if (userResults.length === 0) {
            console.log(`User ${username} not found`);
            return res.status(404).send('User not found');
        }

        const userInfo = userResults[0];
        console.log('User information:', userInfo);

        // Fetch follow status from follows table
        const followerId = req.user.userId; 
        const followedId = userInfo.user_id;

        const getFollowStatusQuery = `
            SELECT status
            FROM follows
            WHERE follower_id = ? AND followed_id = ?
        `;
        db.query(getFollowStatusQuery, [followerId, followedId], (err, followResults) => {
            if (err) {
                console.error('Error fetching follow status:', err);
                return res.status(500).send('Internal Server Error');
            }

            let followStatus = 'Follow'; // Default to Follow if no record found
            if (followResults.length > 0) {
                followStatus = followResults[0].status;
            }

            // Fetch follower and following counts
            const followerCountQuery = 'SELECT COUNT(*) AS followerCount FROM follows WHERE followed_id = ? AND status = "following"';
            const followingCountQuery = 'SELECT COUNT(*) AS followingCount FROM follows WHERE follower_id = ? AND status = "following"';

            db.query(followerCountQuery, [userInfo.user_id], (err, followerResults) => {
                if (err) {
                    console.error('Error fetching follower count:', err);
                    return res.status(500).send('Internal Server Error');
                }

                const followerCount = followerResults[0].followerCount;

                db.query(followingCountQuery, [userInfo.user_id], (err, followingResults) => {
                    if (err) {
                        console.error('Error fetching following count:', err);
                        return res.status(500).send('Internal Server Error');
                    }

                    const followingCount = followingResults[0].followingCount;

                    userInfo.followerCount = followerCount;
                    userInfo.followingCount = followingCount;

                    // Ensure userInfo.user_id is defined and not empty
                    if (!userInfo.user_id) {
                        console.error('user_id is undefined or null:', userInfo.user_id);
                        return res.status(500).send('Internal Server Error');
                    }

                    // Fetch post count from DynamoDB
                    const params = {
                        TableName: 'cloudhive-postdb',
                        KeyConditionExpression: 'userId = :uid',
                        ExpressionAttributeValues: {
                            ':uid': userInfo.user_id.toString()
                        },
                        Select: 'COUNT'
                    };

                    console.log('DynamoDB query params:', params);

                    dynamoDB.query(params, (err, data) => {
                        if (err) {
                            console.error('Error fetching post count:', err);
                            return res.status(500).send('Internal Server Error');
                        }

                        const postCount = data.Count;
                        userInfo.postsCount = postCount;

                        // Optionally, fetch the profile picture URL if it exists
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
                                res.render('profile', { user: userInfo, loggedInUser: req.user, followStatus });
                            });
                        } else {
                            // Render profile.html with user data
                            console.log(`Rendering profile page for ${username}`);
                            res.render('profile', { user: userInfo, loggedInUser: req.user, followStatus });
                        }
                    });
                });
            });
        });
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

    let postImageKey = null;

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

            postImageKey = fileKey; // Store the S3 key instead of the URL
            savePostToDynamoDB(userId, username, content, postImageKey, res);
        });
    } else {
        savePostToDynamoDB(userId, username, content, postImageKey, res);
    }
});

function savePostToDynamoDB(userId, username, content, postImageKey, res) {
    const postId = crypto.randomBytes(16).toString('hex');
    const postTimestamp = new Date().toISOString();

    const params = {
        TableName: 'cloudhive-postdb',
        Item: {
            postId: postId,
            userId: userId,
            username: username,
            content: content,
            postImageKey: postImageKey,
            postTimestamp: postTimestamp
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

app.get('/api/follow/:username', verifyToken, async (req, res) => {
    if (!req.user || !req.user.userId || !req.user.username) {
        console.error('Error: Invalid user information in req.user');
        return res.status(401).send('Unauthorized');
    }

    const followerId = req.user.userId;
    const followerUsername = req.user.username;
    const followedUsername = req.params.username;

    console.log(`Follower ID: ${followerId}`);
    console.log(`Follower Username: ${followerUsername}`);
    console.log(`Followed Username: ${followedUsername}`);

    // Fetch profile user information from database
    const getProfileUserQuery = 'SELECT user_id, username, email FROM users WHERE username = ?';
    db.query(getProfileUserQuery, [followedUsername], async (err, results) => {
        if (err) {
            console.error('Error fetching profile user information:', err);
            return res.status(500).send('Internal Server Error');
        }

        if (results.length === 0) {
            console.log(`Profile user ${followedUsername} not found`);
            return res.status(404).send('Profile user not found');
        }

        const profileUser = results[0];

        console.log('Profile User:', profileUser);

        // Check if follow request already exists
        const checkFollowQuery = `
            SELECT status FROM follows
            WHERE follower_id = ? AND followed_id = ?
        `;
        db.query(checkFollowQuery, [followerId, profileUser.user_id], (err, results) => {
            if (err) {
                console.error('Error checking follow request:', err);
                return res.status(500).send('Internal Server Error');
            }

            if (results.length > 0) {
                const existingStatus = results[0].status;
                if (existingStatus === 'requested') {
                    console.log(`Follow request from ${followerUsername} to ${followedUsername} already pending`);
                    return res.status(400).send('Follow request already pending');
                } else if (existingStatus === 'following') {
                    console.log(`User ${followerUsername} is already following ${followedUsername}`);
                    return res.status(400).send('Already following');
                }
            }

            // Insert follow request into follows table
            const insertFollowQuery = `
                INSERT INTO follows (follower_id, followed_id, status)
                VALUES (?, ?, 'requested')
            `;
            db.query(insertFollowQuery, [followerId, profileUser.user_id], (err, result) => {
                if (err) {
                    console.error('Error inserting follow request:', err);
                    return res.status(500).send('Error inserting follow request');
                }

                console.log(`Follow request from ${followerUsername} to ${followedUsername} initiated successfully`);

                // Prepare Lambda invocation payload
                const lambdaPayload = {
                    body: JSON.stringify({
                        email: profileUser.email, // Email of the requested user
                        followerUsername: followerUsername
                    })
                };

                console.log('Lambda Payload:', lambdaPayload);

                // Prepare Lambda invocation
                const lambdaParams = {
                    FunctionName: 'arn:aws:lambda:us-east-1:576047115698:function:cloudhiveUserFollowedNotification',
                    InvocationType: 'Event',
                    Payload: JSON.stringify(lambdaPayload)
                };

                console.log('Lambda Invocation Params:', lambdaParams);

                // Invoke Lambda function
                lambda.invoke(lambdaParams, (lambdaErr, lambdaData) => {
                    if (lambdaErr) {
                        console.error('Error invoking Lambda function:', lambdaErr);
                    } else {
                        console.log('Lambda function invoked successfully:', lambdaData);
                    }
                });

                res.status(200).send('Follow request initiated');
            });
        });
    });
});

app.get('/api/approve-follow/:username', (req, res) => {
    const requesteeUsername = req.session.username;  // Assuming you store the logged-in username in the session
    const requesterUsername = req.params.username;

    // Get user IDs based on usernames
    const getUserIdsQuery = `
        SELECT user_id, username FROM users WHERE username IN (?, ?)
    `;

    connection.query(getUserIdsQuery, [requesterUsername, requesteeUsername], (err, results) => {
        if (err) return res.status(500).send('Database error');

        const requesterId = results.find(user => user.username === requesterUsername).user_id;
        const requesteeId = results.find(user => user.username === requesteeUsername).user_id;

        // Update follow request status to 'following'
        const updateFollowRequestQuery = `
            UPDATE follows
            SET status = 'following'
            WHERE follower_id = ? AND followed_id = ? AND status = 'requested'
        `;

        connection.query(updateFollowRequestQuery, [requesterId, requesteeId], (err, results) => {
            if (err) return res.status(500).send('Database error');
            res.send('Follow request approved');
        });
    });
});

// Endpoint to fetch follow requests for the logged-in user
app.get('/api/follow-requests', verifyToken, (req, res) => {
    const userId = req.user.userId;

    const fetchRequestsQuery = `
        SELECT users.user_id, users.username, users.first_name, users.last_name, users.profilepic_key
        FROM follows
        JOIN users ON follows.follower_id = users.user_id
        WHERE follows.followed_id = ? AND follows.status = 'requested'
    `;

    db.query(fetchRequestsQuery, [userId], async (err, results) => {
        if (err) {
            console.error('Error fetching follow requests:', err);
            return res.status(500).send('Internal Server Error');
        }

        const followRequests = await Promise.all(results.map(async request => {
            if (request.profilepic_key) {
                const params = {
                    Bucket: 'cloudhive-userdata',
                    Key: request.profilepic_key,
                    Expires: 3600 // 1 hour expiration (in seconds)
                };

                try {
                    const url = await s3.getSignedUrlPromise('getObject', params);
                    request.profile_picture_url = url;
                    console.log(`Presigned URL generated: ${url}`);
                } catch (err) {
                    console.error('Error generating signed URL for profile picture:', err);
                    request.profile_picture_url = '../assets/default-profile.jpg'; // Fallback to default profile picture
                }
            } else {
                request.profile_picture_url = '../assets/default-profile.jpg'; // Fallback to default profile picture
            }
            return request;
        }));

        res.json(followRequests);
    });
});

app.post('/api/follow-requests/accept', verifyToken, (req, res) => {
    const { username } = req.body;
    const followedId = req.user.userId;

    // Fetch the follower's user ID based on the username
    const getFollowerIdQuery = 'SELECT user_id FROM users WHERE username = ?';
    db.query(getFollowerIdQuery, [username], (err, results) => {
        if (err) {
            console.error('Error fetching follower user ID:', err);
            return res.status(500).send('Internal Server Error');
        }

        if (results.length === 0) {
            return res.status(404).send('Follower not found');
        }

        const followerId = results[0].user_id;

        console.log(`Accepting follow request from follower_id: ${followerId} to followed_id: ${followedId}`);

        // Update the follow request status to 'accepted'
        const acceptFollowQuery = `
            UPDATE follows
            SET status = 'following'
            WHERE follower_id = ? AND followed_id = ? AND status = 'requested'
        `;
        db.query(acceptFollowQuery, [followerId, followedId], (err, result) => {
            if (err) {
                console.error('Error accepting follow request:', err);
                return res.status(500).send('Internal Server Error');
            }

            console.log(`Follow request from follower_id: ${followerId} to followed_id: ${followedId} has been accepted`);
            res.status(200).send('Follow request accepted');
        });
    });
});

app.post('/api/follow-requests/deny', verifyToken, (req, res) => {
    const { username } = req.body;
    const followedId = req.user.userId;

    // Fetch the follower's user ID based on the username
    const getFollowerIdQuery = 'SELECT user_id FROM users WHERE username = ?';
    db.query(getFollowerIdQuery, [username], (err, results) => {
        if (err) {
            console.error('Error fetching follower user ID:', err);
            return res.status(500).send('Internal Server Error');
        }

        if (results.length === 0) {
            return res.status(404).send('Follower not found');
        }

        const followerId = results[0].user_id;

        // Remove the follow request from the database
        const denyFollowQuery = `
            DELETE FROM follows
            WHERE follower_id = ? AND followed_id = ? AND status = 'requested'
        `;
        db.query(denyFollowQuery, [followerId, followedId], (err, result) => {
            if (err) {
                console.error('Error denying follow request:', err);
                return res.status(500).send('Internal Server Error');
            }

            res.status(200).send('Follow request denied');
        });
    });
});

app.get('/api/newsfeed', verifyToken, async (req, res) => {
    const loggedInUserId = req.user.userId;
    const { lastTimestamp } = req.query; // Use lastTimestamp from frontend

    // Log the lastTimestamp received from the frontend
    console.log('Received lastTimestamp:', lastTimestamp);

    const getFollowedUsersQuery = `
        SELECT followed_id
        FROM follows
        WHERE follower_id = ? AND status = 'following'
    `;
    
    db.query(getFollowedUsersQuery, [loggedInUserId], async (err, followResults) => {
        if (err) {
            console.error('Error fetching followed users:', err);
            return res.status(500).json({ message: 'Failed to fetch followed users' });
        }

        const followedUserIds = new Set(followResults.map(row => row.followed_id.toString()));
        followedUserIds.add(loggedInUserId.toString());

        let allPosts = [];

        for (const userId of followedUserIds) {
            const params = {
                TableName: 'cloudhive-postdb',
                IndexName: 'userId-postTimestamp-index',
                KeyConditionExpression: 'userId = :userId',
                ExpressionAttributeValues: {
                    ':userId': userId
                },
                Limit: 8,
                ScanIndexForward: false // Descending order
            };

            if (lastTimestamp) {
                params.KeyConditionExpression += ' AND postTimestamp < :lastTimestamp';
                params.ExpressionAttributeValues[':lastTimestamp'] = lastTimestamp;
            }

            try {
                const data = await dynamoDB.query(params).promise();

                // Log the result of the DynamoDB query
                console.log('Fetched posts data from DynamoDB:', data);

                const getUserProfileDataQuery = 'SELECT profilepic_key, first_name FROM users WHERE user_id = ?';
                const userProfileDataResults = await Promise.all(data.Items.map(post => {
                    return new Promise((resolve, reject) => {
                        db.query(getUserProfileDataQuery, [post.userId], (err, userResults) => {
                            if (err) {
                                console.error('Error fetching user profile data:', err);
                                reject(err);
                            } else {
                                resolve({ post, profilepic_key: userResults[0]?.profilepic_key, first_name: userResults[0]?.first_name });
                            }
                        });
                    });
                }));

                // Check if the logged-in user has liked each post
                const likedPostsPromises = data.Items.map(post => {
                    const params = {
                        TableName: 'cloudhive-likes',
                        Key: {
                            postId: post.postId.toString(),
                            userId: loggedInUserId.toString()
                        }
                    };
                    return dynamoDB.get(params).promise().then(result => ({
                        postId: post.postId,
                        isLiked: !!result.Item
                    }));
                });

                const likedPosts = await Promise.all(likedPostsPromises);

                for (const { post, profilepic_key, first_name } of userProfileDataResults) {
                    if (profilepic_key) {
                        const profilePicParams = {
                            Bucket: 'cloudhive-userdata',
                            Key: profilepic_key,
                            Expires: 3600
                        };
                        post.userProfilePicture = await s3.getSignedUrlPromise('getObject', profilePicParams);
                    }
                    if (post.postImageKey) {
                        const postImageParams = {
                            Bucket: 'cloudhive-userdata',
                            Key: post.postImageKey,
                            Expires: 3600
                        };
                        post.imageUrl = await s3.getSignedUrlPromise('getObject', postImageParams);
                    }
                    post.firstName = first_name;

                    // Attach `isLiked` status to the post
                    const likedPost = likedPosts.find(likedPost => likedPost.postId === post.postId);
                    post.isLiked = likedPost ? likedPost.isLiked : false;
                }

                allPosts = allPosts.concat(data.Items);
            } catch (err) {
                console.error('Error fetching posts:', err);
                return res.status(500).json({ message: 'Failed to fetch posts' });
            }
        }

        // Sort and paginate posts
        allPosts.sort((a, b) => new Date(b.postTimestamp).getTime() - new Date(a.postTimestamp).getTime());
        const paginatedPosts = allPosts.slice(0, 8);

        // Log the paginated posts and lastTimestamp for debugging
        console.log('Paginated posts:', paginatedPosts);
        const lastTimestampValue = paginatedPosts.length > 0 ? paginatedPosts[paginatedPosts.length - 1].postTimestamp : null;
        console.log('LastTimestamp to be sent to frontend:', lastTimestampValue);

        res.json({ Items: paginatedPosts, LastEvaluatedKey: lastTimestampValue });
    });
});

app.get('/api/user/:username/posts', verifyToken, async (req, res) => {
    const { username } = req.params;
    const { lastTimestamp } = req.query; // Use lastTimestamp from frontend
    const loggedInUserId = req.user.userId;

    // Log the username and lastTimestamp received from the frontend
    console.log('Received username:', username);
    console.log('Received lastTimestamp:', lastTimestamp);
    console.log('Logged-in user ID:', loggedInUserId);

    // Get user ID from username
    const getUserIdQuery = 'SELECT user_id FROM users WHERE username = ?';
    db.query(getUserIdQuery, [username], async (err, userResults) => {
        if (err) {
            console.error('Error fetching user ID:', err);
            return res.status(500).json({ message: 'Failed to fetch user ID' });
        }

        if (userResults.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const userId = userResults[0].user_id.toString();

        // Log the fetched user ID
        console.log('Fetched user ID:', userId);
        console.log('Type of fetched user ID:', typeof userId);
        console.log('Type of logged-in user ID:', typeof loggedInUserId);

        // Check if the logged-in user is following the requested user or it's their own profile
        const checkFollowQuery = `
            SELECT status
            FROM follows
            WHERE follower_id = ? AND followed_id = ?
        `;

        db.query(checkFollowQuery, [loggedInUserId, userId], async (followErr, followResults) => {
            if (followErr) {
                console.error('Error checking follow status:', followErr);
                return res.status(500).json({ message: 'Failed to check follow status' });
            }

            const isFollowing = followResults.some(row => row.status === 'following');
            const isOwnProfile = loggedInUserId.toString() === userId.toString();
            console.log('loggedinuid: ', loggedInUserId, 'userid: ', userId);

            // Log the follow status and ownership status
            console.log('Is following:', isFollowing);
            console.log('Is own profile:', isOwnProfile);

            if (!isFollowing && !isOwnProfile) {
                return res.status(403).json({ message: 'Not authorized to view posts' });
            }

            let allPosts = [];

            const params = {
                TableName: 'cloudhive-postdb',
                IndexName: 'userId-postTimestamp-index',
                KeyConditionExpression: 'userId = :userId',
                ExpressionAttributeValues: {
                    ':userId': userId
                },
                Limit: 8,
                ScanIndexForward: false // Descending order
            };

            if (lastTimestamp) {
                params.KeyConditionExpression += ' AND postTimestamp < :lastTimestamp';
                params.ExpressionAttributeValues[':lastTimestamp'] = lastTimestamp;
            }

            try {
                const data = await dynamoDB.query(params).promise();

                // Log the result of the DynamoDB query
                console.log('Fetched posts data from DynamoDB:', data);

                const getUserProfileDataQuery = 'SELECT profilepic_key, first_name FROM users WHERE user_id = ?';
                const userProfileDataResults = await Promise.all(data.Items.map(post => {
                    return new Promise((resolve, reject) => {
                        db.query(getUserProfileDataQuery, [post.userId], (err, userResults) => {
                            if (err) {
                                console.error('Error fetching user profile data:', err);
                                reject(err);
                            } else {
                                resolve({ post, profilepic_key: userResults[0]?.profilepic_key, first_name: userResults[0]?.first_name });
                            }
                        });
                    });
                }));

                // Check if the logged-in user has liked each post
                const likedPostsPromises = data.Items.map(post => {
                    const params = {
                        TableName: 'cloudhive-likes',
                        Key: {
                            postId: post.postId.toString(),
                            userId: loggedInUserId.toString()
                        }
                    };
                    return dynamoDB.get(params).promise().then(result => ({
                        postId: post.postId,
                        isLiked: !!result.Item
                    }));
                });

                const likedPosts = await Promise.all(likedPostsPromises);

                for (const { post, profilepic_key, first_name } of userProfileDataResults) {
                    if (profilepic_key) {
                        const profilePicParams = {
                            Bucket: 'cloudhive-userdata',
                            Key: profilepic_key,
                            Expires: 3600
                        };
                        post.userProfilePicture = await s3.getSignedUrlPromise('getObject', profilePicParams);
                    }
                    if (post.postImageKey) {
                        const postImageParams = {
                            Bucket: 'cloudhive-userdata',
                            Key: post.postImageKey,
                            Expires: 3600
                        };
                        post.imageUrl = await s3.getSignedUrlPromise('getObject', postImageParams);
                    }
                    post.firstName = first_name;

                    // Attach `isLiked` status to the post
                    const likedPost = likedPosts.find(likedPost => likedPost.postId === post.postId);
                    post.isLiked = likedPost ? likedPost.isLiked : false;
                }

                allPosts = allPosts.concat(data.Items);
            } catch (err) {
                console.error('Error fetching posts:', err);
                return res.status(500).json({ message: 'Failed to fetch posts' });
            }

            // Sort and paginate posts
            allPosts.sort((a, b) => new Date(b.postTimestamp).getTime() - new Date(a.postTimestamp).getTime());
            const paginatedPosts = allPosts.slice(0, 8);

            // Log the paginated posts and lastTimestamp for debugging
            console.log('Paginated posts:', paginatedPosts);
            const lastTimestampValue = paginatedPosts.length > 0 ? paginatedPosts[paginatedPosts.length - 1].postTimestamp : null;
            console.log('LastTimestamp to be sent to frontend:', lastTimestampValue);

            res.json({ Items: paginatedPosts, LastEvaluatedKey: lastTimestampValue });
        });
    });
});

// Endpoint to like/unlike a post
app.post('/api/like/:postId', verifyToken, async (req, res) => {
    const userId = req.user.userId.toString(); // Convert userId to string
    const postId = req.params.postId.toString(); // Ensure postId is string

    console.log('Received like request');
    console.log('Post ID:', postId);
    console.log('User ID:', userId);

    try {
        // Retrieve the post to get the original poster's userId
        const scanPostParams = {
            TableName: 'cloudhive-postdb',
            FilterExpression: 'postId = :postId',
            ExpressionAttributeValues: { ':postId': postId }
        };

        console.log('Fetching post to get original poster\'s userId:', JSON.stringify(scanPostParams, null, 2));
        const postResult = await dynamoDB.scan(scanPostParams).promise();
        console.log('postresult: ', postResult);

        if (postResult.Items.length === 0) {
            return res.status(404).send('Post not found');
        }

        const postItem = postResult.Items[0];
        const originalPosterId = postItem.userId;

        // Check if the user has already liked the post
        const checkLikeParams = {
            TableName: 'cloudhive-likes',
            Key: { postId: postId, userId: userId }
        };

        console.log('Checking if user has already liked the post:', JSON.stringify(checkLikeParams, null, 2));
        const likeResult = await dynamoDB.get(checkLikeParams).promise();
        console.log('Like check result:', JSON.stringify(likeResult, null, 2));

        let responseMessage;
        let updatedLikeCount;

        if (likeResult.Item) {
            // User has already liked the post, so we remove the like
            const removeLikeParams = {
                TableName: 'cloudhive-likes',
                Key: { postId: postId, userId: userId }
            };

            console.log('Removing like:', JSON.stringify(removeLikeParams, null, 2));
            await dynamoDB.delete(removeLikeParams).promise();

            // Update post like count in cloudhive-postdb
            const updateParams = {
                TableName: 'cloudhive-postdb',
                Key: { userId: originalPosterId, postId: postId },
                UpdateExpression: 'ADD #likes :val',
                ExpressionAttributeNames: { '#likes': 'likes' },
                ExpressionAttributeValues: { ':val': -1 },
                ReturnValues: 'UPDATED_NEW'
            };
            console.log('Updating like count:', JSON.stringify(updateParams, null, 2));
            const updateResult = await dynamoDB.update(updateParams).promise();
            updatedLikeCount = updateResult.Attributes.likes;
            responseMessage = 'Like removed';
        } else {
            // User has not liked the post, so we add the like
            const addLikeParams = {
                TableName: 'cloudhive-likes',
                Item: { postId: postId, userId: userId }
            };

            console.log('Adding like:', JSON.stringify(addLikeParams, null, 2));
            await dynamoDB.put(addLikeParams).promise();

            // Update post like count in cloudhive-postdb
            const updateParams = {
                TableName: 'cloudhive-postdb',
                Key: { userId: originalPosterId, postId: postId },
                UpdateExpression: 'ADD #likes :val',
                ExpressionAttributeNames: { '#likes': 'likes' },
                ExpressionAttributeValues: { ':val': 1 },
                ReturnValues: 'UPDATED_NEW'
            };
            console.log('Updating like count:', JSON.stringify(updateParams, null, 2));
            const updateResult = await dynamoDB.update(updateParams).promise();
            updatedLikeCount = updateResult.Attributes.likes;
            responseMessage = 'Like added';
        }

        res.status(200).json({ message: responseMessage, likes: updatedLikeCount });
    } catch (error) {
        console.error('Error processing like request:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Endpoint to update profile and images
app.post('/api/update_profile', verifyToken, upload.fields([{ name: 'profilePic', maxCount: 1 }, { name: 'headerPic', maxCount: 1 }]), async (req, res) => {
    const userId = req.user.userId;
    const { firstName, lastName, username, email } = req.body;
    const profilePic = req.files['profilePic'] ? req.files['profilePic'][0] : null;
    const headerPic = req.files['headerPic'] ? req.files['headerPic'][0] : null;

    console.log(`Updating profile for user ID: ${userId}`);
    console.log('Received profile picture:', profilePic);
    console.log('Received header picture:', headerPic);

    try {
        // Fetch current user information to check existing keys
        const [currentUser] = await db.promise().query('SELECT profile_pic_key, profile_header_key FROM users WHERE user_id = ?', [userId]);
        const oldProfilePicKey = currentUser[0]?.profile_pic_key;
        const oldHeaderPicKey = currentUser[0]?.profile_header_key;

        // Prepare updates for the user
        const updates = {
            first_name: firstName,
            last_name: lastName,
            username,
            email,
        };

        if (profilePic) {
            // Generate a hashed filename for the profile picture
            const profilePicKey = crypto.randomBytes(12).toString('hex') + '.' + profilePic.originalname.split('.').pop();
            updates.profile_pic_key = profilePicKey;

            // Upload new profile picture to S3
            await s3.putObject({
                Bucket: 'cloudhive-userdata',
                Key: `profile_pic/${profilePicKey}`,
                Body: profilePic.buffer,
                ContentType: profilePic.mimetype
            }).promise();

            console.log('Profile picture uploaded to S3 with key:', profilePicKey);

            // Delete the old profile picture from S3 if it exists
            if (oldProfilePicKey) {
                await s3.deleteObject({
                    Bucket: 'cloudhive-userdata',
                    Key: `profile_pic/${oldProfilePicKey}`
                }).promise();

                console.log('Old profile picture deleted from S3 with key:', oldProfilePicKey);
            }
        }

        if (headerPic) {
            // Generate a hashed filename for the new header picture
            const headerPicKey = crypto.randomBytes(12).toString('hex') + '.' + headerPic.originalname.split('.').pop();
            updates.profile_header_key = headerPicKey;

            // Upload new header picture to S3
            await s3.putObject({
                Bucket: 'cloudhive-userdata',
                Key: `header_pic/${headerPicKey}`,
                Body: headerPic.buffer,
                ContentType: headerPic.mimetype
            }).promise();

            console.log('Header picture uploaded to S3 with key:', headerPicKey);

            // Delete the old header picture from S3 if it exists
            if (oldHeaderPicKey) {
                await s3.deleteObject({
                    Bucket: 'cloudhive-userdata',
                    Key: `header_pic/${oldHeaderPicKey}`
                }).promise();

                console.log('Old header picture deleted from S3 with key:', oldHeaderPicKey);
            }
        }

        // Update user record in database
        await db.promise().query('UPDATE users SET ? WHERE user_id = ?', [updates, userId]);

        res.status(200).json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Error processing update:', error);
        res.status(500).json({ error: 'Failed to process update' });
    }
});

app.use((req, res) => {
    res.redirect('/');
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
