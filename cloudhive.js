// cloudhive Backend
// for EC2, built with nodejs and <3
// July 2024

// Import Modules 
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken'); 
const cookieParser = require('cookie-parser');
const AWS = require('aws-sdk'); 
const fs = require('fs');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const rateLimit = require('express-rate-limit');
const db = require('./config'); 
const app = express();
const upload = multer({ storage: multer.memoryStorage() });
const TABLE_NAME = 'cloudhive-postdb';

// Trust proxy as we're running behind a load balancer
app.set('trust proxy', true);

// Server runs on port 8080 (HTTP)
const port = 8080;

// .env configuration and Secrets
require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET;

// AWS 
const dynamoDB = new AWS.DynamoDB.DocumentClient({ region: 'us-east-1' });
const lambda = new AWS.Lambda({region: 'us-east-1'});
const s3 = new AWS.S3({
    region: 'us-east-1', 
    signatureVersion: 'v4'
});

// View Engine EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Max File Transfer Size 10MB
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Health Check Endpoint for Amazon ELB 
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

// Create a rate limiter
const registerRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes window
    max: 100, // Limit each IP to 100 requests per window
    message: 'Too many requests from this IP, please try again later.',
    keyGenerator: (req) => {
        // Get the IP address from 'X-Forwarded-For' or default to remoteAddress as we're behind a proxy (load balancer)
        const ip = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0] : req.connection.remoteAddress;
        return ip;
    }
});

// Middleware to log IP address
const logIpAddress = (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0] : req.connection.remoteAddress;
    console.log(`IP Address: ${ip} - Requested URL: ${req.originalUrl} - Method: ${req.method}`);
    next();
};

// Register endpoint
app.post('/api/register', logIpAddress, registerRateLimiter, async (req, res) => {
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
                const token = jwt.sign({ userId, username, email }, JWT_SECRET, { expiresIn: '2h' });

                // Send the token as part of the response
                res.cookie('token', token, { httpOnly: true, secure: true });

                console.log('User registered successfully:', result);

                // Prepare payload for Lambda
                const payload = {
                    body: JSON.stringify({
                        email: email,
                        username: username
                    })
                };

                // Invoke Lambda function to send a welcome email
                const lambdaParams = {
                    FunctionName: 'arn:aws:lambda:us-east-1:576047115698:function:cloudhiveWelcomeEmail', 
                    InvocationType: 'Event', 
                    Payload: JSON.stringify(payload)
                };

                lambda.invoke(lambdaParams, (lambdaErr, data) => {
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
        console.log('no token found. redirecting to login');
        return res.status(401).json();
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            console.log('token error! redirecting...')
            return res.status(401).json({ redirect: '/' });
        }

        req.user = decoded;

        // Log user information
        console.log('User logged in:', req.user);

        next();
    });
};

// New login and fetch user info endpoint
app.post('/api/login_redirect', (req, res) => {
    const { identifier, password } = req.body; 

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

            // Fetch complete user information including email
            db.query('SELECT username, email, first_name, last_name FROM users WHERE user_id = ?', [user.user_id], (err, results) => {
                if (err) {
                    console.error('Error fetching user information:', err);
                    return res.status(500).json({ error: 'Failed to fetch user information' });
                }

                if (results.length === 0) {
                    return res.status(404).json({ error: 'User not found' });
                }

                const userInfo = results[0];

                // Generate JWT token with correct user information
                const token = jwt.sign({ userId: user.user_id, username: userInfo.username, email: userInfo.email }, JWT_SECRET, { expiresIn: '2h' });
                console.log('email used: ', userInfo.email);

                // Log token generation
                console.log('JWT Token Generated:', token);

                // Send token in a cookie
                res.cookie('token', token, { httpOnly: true, secure: true });

                // Check if required fields are empty
                if (!userInfo.first_name || !userInfo.last_name) {
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

    // Update last activity timestamp
    const updateTimestampQuery = 'UPDATE users SET last_activity = NOW() WHERE user_id = ?';
    db.query(updateTimestampQuery, [userId], (updateErr) => {
        if (updateErr) {
            console.error('Error updating last activity timestamp:', updateErr);
            return res.status(500).json({ error: 'Failed to update last activity timestamp' });
        }

        // Fetch user information from db
        const fetchUserInfoQuery = 'SELECT first_name, last_name, profilepic_key, username, email FROM users WHERE user_id = ?';
        db.query(fetchUserInfoQuery, [userId], (fetchErr, results) => {
            if (fetchErr) {
                console.error('Error fetching user information:', fetchErr);
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
                    Expires: 60 * 60
                };
                s3.getSignedUrl('getObject', params, (s3Err, url) => {
                    if (s3Err) {
                        console.error('Error generating presigned URL:', s3Err);
                        return res.status(500).json({ error: 'Failed to generate presigned URL' });
                    }
                    // Send the presigned profile URL to the frontend 
                    userInfo.profile_picture_url = url;
                    res.status(200).json({ userInfo });
                });
            } else {
                // If no profile picture, do not send presigned URL 
                res.status(200).json({ userInfo });
            }
        });
    });
});

app.post('/api/onboard_profile_update', verifyToken, upload.single('profilePic'), (req, res) => {
    if (!req.file) {
        console.log('No file uploaded');
        return res.status(400).json({ error: 'No file uploaded' });
    }

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

    const randomString = crypto.randomBytes(12).toString('hex');
    const profilePicKey = `profile-pics/${randomString}.${extension}`;

    // Create S3 upload parameters
    const params = {
        Bucket: 'cloudhive-userdata',
        Key: profilePicKey,
        Body: req.file.buffer,
        ContentType: req.file.mimetype,
        ACL: 'private'
    };

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

        // Update user information in the database
        db.query('UPDATE users SET profile_pic = ?, profilepic_key = ?, first_name = ?, last_name = ? WHERE user_id = ?',
            [profilePicUrl, profilePicKey, firstName, lastName, req.user.userId],
            (err, result) => {
                if (err) {
                    console.error('Error updating user information in database:', err);
                    return res.status(500).json({ error: 'Failed to update user information' });
                }

                // Notify user registration is successful
                res.status(200).json({ message: 'Profile picture and user information updated successfully', profilePicUrl });
            });
    });
});

app.get('/search', verifyToken, (req, res) => {
    const query = req.query.query;

    if (!query) {
        return res.status(400).send('No search query provided');
    }

    // Retrieve the logged-in user information from the session or token
    const loggedInUser = req.user; 

    console.log(`Search query: ${query}`);

    const searchQuery = `
        SELECT username, first_name, last_name, profilepic_key
        FROM users
        WHERE username LIKE ? OR first_name LIKE ? OR last_name LIKE ?
    `;
    const searchParams = [`%${query}%`, `%${query}%`, `%${query}%`];

    db.query(searchQuery, searchParams, (err, results) => {
        if (err) {
            console.error('Error fetching search results:', err);
            return res.status(500).send('Internal Server Error');
        }

        console.log('Search results:', results);

        const s3Promises = results.map(user => {
            if (user.profilepic_key) {
                const params = {
                    Bucket: 'cloudhive-userdata',
                    Key: user.profilepic_key,
                    Expires: 3600 // 1 hour expiration (in seconds)
                };
                return new Promise((resolve, reject) => {
                    s3.getSignedUrl('getObject', params, (err, url) => {
                        if (err) {
                            console.error('Error generating presigned URL:', err);
                            reject(err);
                        } else {
                            user.profile_picture_url = url;
                            resolve(user);
                        }
                    });
                });
            } else {
                user.profile_picture_url = '../assets/default-profile.jpg'; // Fallback image
                return Promise.resolve(user);
            }
        });

        Promise.all(s3Promises).then(users => {
            // Render the search results page with users and loggedInUser
            res.render('results', { users, loggedInUser });
        }).catch(err => {
            console.error('Error during S3 operations:', err);
            res.status(500).send('Internal Server Error');
        });
    });
});

// Endpoint to fetch friends data with token verification
app.get('/api/friends', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Fetch friends list from the database
        const friends = await db.query(`
            SELECT u.user_id, u.username, u.first_name, u.last_name, u.profile_pic AS profile_picture_url,
                   (SELECT COUNT(*) FROM follows WHERE follower_id = u.user_id) AS following_count,
                   (SELECT COUNT(*) FROM follows WHERE followed_id = u.user_id) AS followers_count
            FROM users u
            JOIN follows f ON (f.follower_id = u.user_id OR f.followed_id = u.user_id)
            WHERE f.follower_id = ? OR f.followed_id = ?
        `, [userId, userId]);

        res.json({ friends });
    } catch (error) {
        console.error('Error fetching friends:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Endpoint for user profile 
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

            // Defaults to Follow status if there is no record found in the database. 
            let followStatus = 'Follow';
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

                        // Presign the profile picture URL if present in db 
                        const s3Operations = [];

                        if (userInfo.profilepic_key) {
                            const profilePicParams = {
                                Bucket: 'cloudhive-userdata',
                                Key: `${userInfo.profilepic_key}`,
                                Expires: 3600 // seconds
                            };
                            s3Operations.push(
                                new Promise((resolve, reject) => {
                                    s3.getSignedUrl('getObject', profilePicParams, (err, url) => {
                                        if (err) {
                                            console.error('Error generating presigned URL for profile picture:', err);
                                            reject(err);
                                        } else {
                                            userInfo.profile_picture_url = url;
                                            console.log('Profile picture presigned URL:', url);
                                            resolve();
                                        }
                                    });
                                })
                            );
                        }

                        // Presign the header picture URL if it exists in db 
                        if (userInfo.profile_header_key) {
                            const headerPicParams = {
                                Bucket: 'cloudhive-userdata',
                                Key: `${userInfo.profile_header_key}`,
                                Expires: 3600 // seconds
                            };
                            s3Operations.push(
                                new Promise((resolve, reject) => {
                                    s3.getSignedUrl('getObject', headerPicParams, (err, url) => {
                                        if (err) {
                                            console.error('Error generating presigned URL for header picture:', err);
                                            reject(err);
                                        } else {
                                            userInfo.profile_header_url = url;
                                            console.log('Header picture presigned URL:', url);
                                            resolve();
                                        }
                                    });
                                })
                            );
                        }

                        // Execute all S3 operations
                        Promise.all(s3Operations).then(() => {
                            console.log(`Rendering profile page for ${username}`);
                            res.render('profile', { user: userInfo, loggedInUser: req.user, followStatus });
                        }).catch(err => {
                            console.error('Error during S3 operations:', err);
                            res.status(500).send('Internal Server Error');
                        });
                    });
                });
            });
        });
    });
});

app.post('/api/create_post', verifyToken, upload.single('postImage'), (req, res) => {
    const { content } = req.body;
    const userId = req.user.userId.toString(); // Converts UID to string as the db is set up as string. 
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

// Global function to save post to DynamoDB database
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

// Follow endpoint for following a user
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
                return res.status(500).send('Internal Server Error');
            }

            if (results.length > 0) {
                const existingStatus = results[0].status;
                if (existingStatus === 'requested') {
                    return res.status(400).send('Follow request already pending');
                } else if (existingStatus === 'following') {
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

                // Prepare Lambda invocation payload
                const lambdaPayload = {
                    body: JSON.stringify({
                        email: profileUser.email,
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

// Endpoint to accept follow request from user
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

// Endpoint to deny follow request 
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
    const { lastTimestamp } = req.query; // Utilises last timestamp from frontend for pagination 

    // Create DB query 
    const getFollowedUsersQuery = `
        SELECT followed_id
        FROM follows
        WHERE follower_id = ? AND status = 'following'
    `;
    
    // Query DB for followed users
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

                // Check if the user has liked any posts in the feed
                const likedPostsPromises = data.Items.map(post => {
                    const params = {
                        TableName: 'cloudhive-likes',
                        Key: {
                            postId: post.postId.toString(), // Ensures the items are indexable by the db as the partition key is a String
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

                    // Add `isUserPost` flag
                    post.isUserPost = post.userId.toString() === loggedInUserId.toString();
                }

                allPosts = allPosts.concat(data.Items);
            } catch (err) {
                return res.status(500).json({ message: 'Failed to fetch posts' });
            }
        }

        // Sort and paginate posts
        allPosts.sort((a, b) => new Date(b.postTimestamp).getTime() - new Date(a.postTimestamp).getTime());
        const paginatedPosts = allPosts.slice(0, 8);

        // Log the paginated posts and lastTimestamp for debugging
        const lastTimestampValue = paginatedPosts.length > 0 ? paginatedPosts[paginatedPosts.length - 1].postTimestamp : null;
        res.json({ Items: paginatedPosts, LastEvaluatedKey: lastTimestampValue });
    });
});

// Endpoint to view user posts and generate profile feed
app.get('/api/user/:username/posts', verifyToken, async (req, res) => {
    const { username } = req.params;
    const { lastTimestamp } = req.query;
    const loggedInUserId = req.user.userId;

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

        console.log('Fetched user ID:', userId);

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
                ScanIndexForward: false
            };

            if (lastTimestamp) {
                params.KeyConditionExpression += ' AND postTimestamp < :lastTimestamp';
                params.ExpressionAttributeValues[':lastTimestamp'] = lastTimestamp;
            }

            try {
                const data = await dynamoDB.query(params).promise();

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
                    const likedPost = likedPosts.find(likedPost => likedPost.postId === post.postId);
                    post.isLiked = likedPost ? likedPost.isLiked : false;

                    // Add `isUserPost` flag
                    post.isUserPost = post.userId.toString() === loggedInUserId.toString();
                }

                allPosts = allPosts.concat(data.Items);
            } catch (err) {
                console.error('Error fetching posts:', err);
                return res.status(500).json({ message: 'Failed to fetch posts' });
            }

            allPosts.sort((a, b) => new Date(b.postTimestamp).getTime() - new Date(a.postTimestamp).getTime());
            const paginatedPosts = allPosts.slice(0, 8);
            const lastTimestampValue = paginatedPosts.length > 0 ? paginatedPosts[paginatedPosts.length - 1].postTimestamp : null;
            console.log('LastTimestamp to be sent to frontend:', lastTimestampValue);

            res.json({ Items: paginatedPosts, LastEvaluatedKey: lastTimestampValue });
        });
    });
});

// Endpoint to like/unlike a post
app.post('/api/like/:postId', verifyToken, async (req, res) => {
    const userId = req.user.userId.toString();
    const postId = req.params.postId.toString(); 

    try {
        // Retrieve the post to get the original poster's user id 
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
        const likeResult = await dynamoDB.get(checkLikeParams).promise();
        let responseMessage;
        let updatedLikeCount;

        if (likeResult.Item) {
            // User has already liked the post, so remove like
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
            // User has not liked the post, so like is added
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

// Update profile endpoint 
app.post('/api/update_profile', verifyToken, upload.fields([{ name: 'profilePic', maxCount: 1 }, { name: 'headerPic', maxCount: 1 }]), (req, res) => {
    if (!req.user || !req.user.userId) {
        return res.status(401).json({ error: 'User not authenticated' });
    }

    const userId = req.user.userId;
    const { firstName, lastName, username, email } = req.body;
    const profilePic = req.files['profilePic'] ? req.files['profilePic'][0] : null;
    const headerPic = req.files['headerPic'] ? req.files['headerPic'][0] : null;

    // Fetch the current user data
    db.query('SELECT profilepic_key, profile_header_key FROM users WHERE user_id = ?', [userId], (err, results) => {
        if (err) {
            console.error('Error fetching user data:', err);
            return res.status(500).json({ error: 'Failed to fetch user data' });
        }

        const currentUser = results[0];
        const oldProfilePicKey = currentUser.profilepic_key;
        const oldHeaderPicKey = currentUser.profile_header_key;

        const updates = {
            first_name: firstName,
            last_name: lastName,
            username,
        };

        // Function to upload image to S3
        const uploadToS3 = (file, folder) => {
            return s3.upload({
                Bucket: 'cloudhive-userdata',
                Key: `${folder}/${crypto.randomBytes(12).toString('hex')}.jpeg`,
                Body: file.buffer,
                ContentType: file.mimetype
            }).promise();
        };

        // Delete old image from S3
        const deleteFromS3 = (key) => {
            return s3.deleteObject({
                Bucket: 'cloudhive-userdata',
                Key: `${key}`
            }).promise();
        };

        const s3Operations = [];

        if (profilePic) {
            // Upload new profile picture and delete old one if exists
            s3Operations.push(uploadToS3(profilePic, 'profile-pics').then(data => {
                updates.profilepic_key = data.Key;
                updates.profile_pic = data.Location;

                if (oldProfilePicKey) {
                    return deleteFromS3(oldProfilePicKey).then(() => {
                    });
                }
            }));
        } else {
            // If no new profile picture, retain the old key and URL
            updates.profilepic_key = oldProfilePicKey;
            updates.profile_pic = oldProfilePicKey ? `https://cloudhive-userdata.s3.amazonaws.com/${oldProfilePicKey}` : null;
        }

        if (headerPic) {
            // Upload new header picture and delete old one if exists
            s3Operations.push(uploadToS3(headerPic, 'header_pic').then(data => {
                updates.profile_header_key = data.Key;
                updates.profile_header = data.Location; // Save the URL
                console.log('Header picture uploaded to S3 with URL:', data.Location);

                if (oldHeaderPicKey) {
                    return deleteFromS3(oldHeaderPicKey).then(() => {
                        console.log('Old header picture deleted from S3');
                    });
                }
            }));
        } else {
            // If no new header picture, retain the old key and URL
            updates.profile_header_key = oldHeaderPicKey;
            updates.profile_header = oldHeaderPicKey ? `https://cloudhive-userdata.s3.amazonaws.com/header_pic/${oldHeaderPicKey}` : null;
        }

        // Execute S3 operations and then update the database
        Promise.all(s3Operations).then(() => {
            // Update user profile
            db.query('UPDATE users SET ? WHERE user_id = ?', [updates, userId], (err, results) => {
                if (err) {
                    console.error('Error updating user profile:', err);
                    return res.status(500).json({ error: 'Failed to update profile' });
                }

                res.status(200).json({ message: 'Profile updated successfully' });
            });
        }).catch(err => {
            console.error('Error during S3 operations:', err);
            res.status(500).json({ error: 'Failed to process image uploads' });
        });
    });
});

// Update password endpoint
app.post('/api/change_password', verifyToken, (req, res) => {
    const { currentPassword, newPassword, confirmNewPassword } = req.body;

    // Ensure all fields are provided, this is validated in the frontend but we will do a backend verification just to be safe. 
    if (!currentPassword || !newPassword || !confirmNewPassword) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if new passwords match. This is also validated in the frontend already, but will verifiy in the backend to be safe. 
    if (newPassword !== confirmNewPassword) {
        return res.status(400).json({ error: 'New password and confirmation do not match' });
    }

    // Extract userId from the token
    const userId = req.user.userId;

    // Query the database for the user's current password hash
    db.query('SELECT password_hash FROM users WHERE user_id = ?', [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = results[0];

        // Compare the provided current password with the stored hash
        bcrypt.compare(currentPassword, user.password_hash, (bcryptErr, bcryptRes) => {
            if (bcryptErr || !bcryptRes) {
                return res.status(401).json({ error: 'Current password is incorrect' });
            }

            // Hash the new password
            bcrypt.hash(newPassword, 10, (hashErr, hashedPassword) => {
                if (hashErr) {
                    console.error('Error hashing new password:', hashErr);
                    return res.status(500).json({ error: 'Failed to hash new password' });
                }

                // Update the password in the database
                db.query('UPDATE users SET password_hash = ? WHERE user_id = ?', [hashedPassword, userId], (updateErr) => {
                    if (updateErr) {
                        console.error('Error updating password:', updateErr);
                        return res.status(500).json({ error: 'Failed to update password' });
                    }

                    res.status(200).json({ message: 'Password changed successfully' });
                });
            });
        });
    });
});

// Endpoint to change user email 
app.post('/api/change_email', verifyToken, (req, res) => {
    const { newEmail } = req.body;
    const userId = req.user.userId; 

    // Validate the new email
    if (!newEmail || !newEmail.includes('@')) {
        return res.status(400).json({ error: 'Invalid email address' });
    }

    // Check if the new email is already in use
    db.query('SELECT * FROM users WHERE email = ?', [newEmail], (err, results) => {
        if (err) {
            console.error('Error checking email:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length > 0) {
            return res.status(400).json({ error: 'Email address is already in use' });
        }

        // Update the email in the database
        db.query('UPDATE users SET email = ? WHERE user_id = ?', [newEmail, userId], (err) => {
            if (err) {
                console.error('Error updating email:', err);
                return res.status(500).json({ error: 'Failed to update email' });
            }

            res.status(200).json({ message: 'Email updated successfully' });
        });
    });
});

// Cancel follow request endpoint
app.delete('/api/cancel-follow/:username', verifyToken, async (req, res) => {
    try {
        // Get the username from the request
        const followedUsername = req.params.username;

        // Get the logged in user's ID from the token
        const { userId } = req.user;

        // Perform the query to get the user_id of the user to be unfollowed
        db.query(
            'SELECT user_id FROM users WHERE username = ?',
            [followedUsername],
            async (err, results) => {
                if (err) {
                    console.error('Database query error:', err);
                    return res.status(500).json({ message: 'Internal server error' });
                }

                // Check if user was found
                if (results.length === 0) {
                    return res.status(404).json({ message: 'User not found' });
                }

                const followedUserId = results[0].user_id;

                // Perform the delete operation
                db.query(
                    'DELETE FROM follows WHERE follower_id = ? AND followed_id = ? AND status = "requested"',
                    [userId, followedUserId],
                    (deleteErr, deleteResults) => {
                        if (deleteErr) {
                            console.error('Delete operation error:', deleteErr);
                            return res.status(500).json({ message: 'Internal server error' });
                        }

                        // Check if any rows were affected
                        if (deleteResults.affectedRows === 0) {
                            return res.status(404).json({ message: 'Follow request not found' });
                        }

                        res.status(200).json({ message: 'Follow request canceled successfully' });
                    }
                );
            }
        );
    } catch (error) {
        console.error('Error canceling follow request:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Unfollow user endpoint
app.delete('/api/unfollow/:username', verifyToken, async (req, res) => {
    try {
        // Get the username from the request parameters
        const followedUsername = req.params.username;

        // Get the signed in user id from the token
        const { userId } = req.user;

        // Perform the query to get the user id of the user to be unfollowed
        db.query(
            'SELECT user_id FROM users WHERE username = ?',
            [followedUsername],
            async (err, results) => {
                if (err) {
                    console.error('Database query error:', err);
                    return res.status(500).json({ message: 'Internal server error' });
                }

                // Check if user was found
                if (results.length === 0) {
                    return res.status(404).json({ message: 'User not found' });
                }

                const followedUserId = results[0].user_id;

                // Perform the unfollow request
                db.query(
                    'DELETE FROM follows WHERE follower_id = ? AND followed_id = ? AND status = "following"',
                    [userId, followedUserId],
                    (deleteErr, deleteResults) => {
                        if (deleteErr) {
                            return res.status(500).json({ message: 'Internal server error' });
                        }

                        // Check if any rows were affected
                        if (deleteResults.affectedRows === 0) {
                            return res.status(404).json({ message: 'Following relationship not found' });
                        }

                        res.status(200).json({ message: 'User unfollowed successfully' });
                    }
                );
            }
        );
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Fetch users that the user is following endpoint
app.get('/api/following', verifyToken, (req, res) => {
    const userId = req.user.userId; 

    const fetchFollowingQuery = `
        SELECT users.user_id, users.username, users.first_name, users.last_name, users.profilepic_key
        FROM follows
        JOIN users ON follows.followed_id = users.user_id
        WHERE follows.follower_id = ?
    `;

    db.query(fetchFollowingQuery, [userId], async (err, results) => {
        if (err) {
            console.error('Error fetching following users:', err);
            return res.status(500).send('Internal Server Error');
        }

        const followingUsers = await Promise.all(results.map(async user => {
            if (user.profilepic_key) {
                const params = {
                    Bucket: 'cloudhive-userdata',
                    Key: user.profilepic_key,
                    Expires: 3600
                };

                try {
                    const url = await s3.getSignedUrlPromise('getObject', params);
                    user.profile_picture_url = url;
                    console.log(`Presigned URL generated: ${url}`);
                } catch (err) {
                    console.error('Error generating signed URL for profile picture:', err);
                    user.profile_picture_url = '../assets/default-profile.jpg'; // Fallback to default profile picture
                }
            } else {
                user.profile_picture_url = '../assets/default-profile.jpg'; // Fallback to default profile picture
            }
            return user;
        }));

        res.json(followingUsers);
    });
});

// Fetch users who are following the user
app.get('/api/followers', verifyToken, (req, res) => {
    const userId = req.user.userId;

    const fetchFollowersQuery = `
        SELECT users.user_id, users.username, users.first_name, users.last_name, users.profilepic_key
        FROM follows
        JOIN users ON follows.follower_id = users.user_id
        WHERE follows.followed_id = ?
    `;

    db.query(fetchFollowersQuery, [userId], async (err, results) => {
        if (err) {
            console.error('Error fetching followers:', err);
            return res.status(500).send('Internal Server Error');
        }

        const followers = await Promise.all(results.map(async user => {
            if (user.profilepic_key) {
                const params = {
                    Bucket: 'cloudhive-userdata',
                    Key: user.profilepic_key,
                    Expires: 3600 // seconds
                };

                try {
                    const url = await s3.getSignedUrlPromise('getObject', params);
                    user.profile_picture_url = url;
                    console.log(`Presigned URL generated: ${url}`);
                } catch (err) {
                    console.error('Error generating signed URL for profile picture:', err);
                    user.profile_picture_url = '../assets/default-profile.jpg'; // Fallback to default profile picture
                }
            } else {
                user.profile_picture_url = '../assets/default-profile.jpg'; // Fallback to default profile picture
            }
            return user;
        }));

        res.json(followers);
    });
});

// Delete post endpoint 
app.delete('/api/posts/:postId', verifyToken, async (req, res) => {
    const postId = req.params.postId;
    const userId = req.user.userId; 

    try {
        // Check if the post belongs to the user
        const getPostParams = {
            TableName: 'cloudhive-postdb',
            Key: {
                userId: userId.toString(), 
                postId: postId.toString()
            }
        };

        const postResult = await dynamoDB.get(getPostParams).promise();
        const post = postResult.Item;

        if (!post) {
            return res.status(404).json({ message: 'Post not found.' });
        }

        if (post.userId.toString() !== userId.toString()) {
            return res.status(403).json({ message: 'You do not have permission to delete this post.' });
        }

        // Check if the post has an associated image
        if (post.postImageKey) {
            const deleteImageParams = {
                Bucket: 'cloudhive-userdata',
                Key: post.postImageKey
            };

            // Delete the image from S3
            await s3.deleteObject(deleteImageParams).promise();
            console.log(`Deleted image from S3: ${post.postImageKey}`);
        }

        // Proceed with deletion from DynamoDB
        const deletePostParams = {
            TableName: 'cloudhive-postdb',
            Key: {
                userId: userId.toString(), 
                postId: postId.toString()
            }
        };

        await dynamoDB.delete(deletePostParams).promise();

        res.status(200).json({ message: 'Post and associated image deleted successfully.' });
    } catch (error) {
        console.error('Error deleting post:', error);
        res.status(500).json({ message: 'An error occurred while deleting the post.' });
    }
});

// Redirect to homepage 
app.use((req, res) => {
    res.redirect('/');
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});