require('dotenv').config();
const express = require('express');
const path = require('path');
const { google } = require('googleapis');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Firebase Admin
try {
    admin.initializeApp({
        credential: admin.credential.cert({
            projectId: process.env.FIREBASE_PROJECT_ID,
            privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        }),
        projectId: process.env.FIREBASE_PROJECT_ID
    });
    console.log('✅ Firebase Admin initialized successfully');
} catch (error) {
    console.error('❌ Firebase initialization error:', error.message);
    process.exit(1);
}

const db = admin.firestore();

// Middleware
app.use(express.json());
app.use(express.static('public'));

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = '7d'; // 7 days

// Google OAuth Configuration
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const BASE_URL = process.env.NODE_ENV === 'production'
    ? process.env.RENDER_EXTERNAL_URL || process.env.BASE_URL || 'https://sheeter-lb5v.onrender.com'
    : `http://localhost:${PORT}`;
const REDIRECT_URI = `${BASE_URL}/auth/callback`;
const SCOPES = [
    'https://www.googleapis.com/auth/spreadsheets',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
];
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// Validate required environment variables
const requiredEnvVars = {
    GOOGLE_CLIENT_ID: CLIENT_ID,
    GOOGLE_CLIENT_SECRET: CLIENT_SECRET,
    ENCRYPTION_KEY: ENCRYPTION_KEY,
    FIREBASE_PROJECT_ID: process.env.FIREBASE_PROJECT_ID,
    FIREBASE_CLIENT_EMAIL: process.env.FIREBASE_CLIENT_EMAIL,
    FIREBASE_PRIVATE_KEY: process.env.FIREBASE_PRIVATE_KEY
};

const missingVars = Object.entries(requiredEnvVars)
    .filter(([key, value]) => !value)
    .map(([key]) => key);

if (missingVars.length > 0) {
    console.error('❌ Missing required environment variables:', missingVars.join(', '));
    process.exit(1);
}

// Create OAuth2 client
const oauth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);

// JWT Functions
function generateUserToken(userId, email, apiKey) {
    return jwt.sign(
        { 
            userId, 
            email, 
            apiKey,
            type: 'auth',
            iat: Math.floor(Date.now() / 1000)
        },
        JWT_SECRET,
        { 
            expiresIn: JWT_EXPIRES_IN,
            issuer: 'sheeter-api',
            audience: 'sheeter-users'
        }
    );
}

function verifyUserToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET, {
            issuer: 'sheeter-api',
            audience: 'sheeter-users'
        });
    } catch (error) {
        console.error('JWT verification failed:', error.message);
        return null;
    }
}

// Encryption functions
function encrypt(text) {
    console.log('🔐 Starting encryption process...');
    
    if (!ENCRYPTION_KEY) {
        throw new Error('ENCRYPTION_KEY is not configured');
    }
    
    try {
        const key = Buffer.from(ENCRYPTION_KEY, 'base64');
        console.log(`🔑 Key decoded successfully: ${key.length} bytes`);
        
        if (key.length !== 32) {
            throw new Error(`ENCRYPTION_KEY must decode to 32 bytes, got ${key.length} bytes`);
        }
        
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        console.log('✅ Encryption successful');
        return {
            encrypted,
            iv: iv.toString('hex')
        };
    } catch (error) {
        console.error('❌ Encryption failed:', {
            error: error.message,
            keyLength: ENCRYPTION_KEY ? ENCRYPTION_KEY.length : 'undefined',
            keyPreview: ENCRYPTION_KEY ? `${ENCRYPTION_KEY.substring(0, 8)}...` : 'undefined'
        });
        throw error;
    }
}

function decrypt(encryptedData) {
    if (!ENCRYPTION_KEY) {
        throw new Error('ENCRYPTION_KEY is not configured');
    }
    
    try {
        const key = Buffer.from(ENCRYPTION_KEY, 'base64');
        const iv = Buffer.from(encryptedData.iv, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        console.error('❌ Decryption error:', error.message);
        throw error;
    }
}

// Generate secure API key
function generateApiKey() {
    return 'sk_' + crypto.randomBytes(32).toString('hex');
}

// Generate user ID from email
function generateUserId(email) {
    return crypto.createHash('sha256').update(email).digest('hex').substring(0, 16);
}

// Get or create user API key
async function getOrCreateUserApiKey(email, googleTokens) {
    const userId = generateUserId(email);
    const userRef = db.collection('user-credentials').doc(userId);

    try {
        const doc = await userRef.get();

        if (doc.exists) {
            const userData = doc.data();
            const encryptedTokens = encrypt(JSON.stringify(googleTokens));

            await userRef.update({
                encryptedTokens: encryptedTokens,
                lastAccess: admin.firestore.FieldValue.serverTimestamp(),
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            });

            console.log(`✅ Updated tokens for existing user: ${email}`);
            return userData.apiKey;

        } else {
            const apiKey = generateApiKey();
            const apiKeyHash = await bcrypt.hash(apiKey, 12);
            const encryptedTokens = encrypt(JSON.stringify(googleTokens));

            await userRef.set({
                userId: userId,
                email: email,
                apiKey: apiKey,
                apiKeyHash: apiKeyHash,
                encryptedTokens: encryptedTokens,
                createdAt: admin.firestore.FieldValue.serverTimestamp(),
                lastAccess: admin.firestore.FieldValue.serverTimestamp()
            });

            console.log(`✅ Created new API key for user: ${email}`);
            return apiKey;
        }

    } catch (error) {
        console.error('❌ Firebase error:', error);
        throw error;
    }
}

// JWT Authentication Middleware
function authenticateJWT(req, res, next) {
    // Check for JWT in Authorization header or cookies
    let token = null;
    
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
    } else if (req.headers.cookie) {
        // Extract from cookie
        const cookies = req.headers.cookie.split(';').reduce((acc, cookie) => {
            const [key, value] = cookie.trim().split('=');
            acc[key] = value;
            return acc;
        }, {});
        token = cookies['sheeter-auth'];
    }
    
    if (!token) {
        return res.status(401).json({
            error: 'No authentication token provided'
        });
    }
    
    const decoded = verifyUserToken(token);
    if (!decoded) {
        return res.status(401).json({
            error: 'Invalid or expired authentication token'
        });
    }
    
    req.user = {
        userId: decoded.userId,
        email: decoded.email,
        apiKey: decoded.apiKey
    };
    
    next();
}

// API Key Authentication (for external API calls)
async function authenticateApiKey(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            error: 'Missing or invalid authorization header. Use: Authorization: Bearer YOUR_API_KEY'
        });
    }

    const apiKey = authHeader.substring(7);

    try {
        const snapshot = await db.collection('user-credentials')
            .where('apiKey', '==', apiKey)
            .limit(1)
            .get();

        if (snapshot.empty) {
            return res.status(401).json({ error: 'Invalid API key' });
        }

        const userDoc = snapshot.docs[0];
        const userData = userDoc.data();
        const googleTokens = JSON.parse(decrypt(userData.encryptedTokens));

        await userDoc.ref.update({
            lastAccess: admin.firestore.FieldValue.serverTimestamp()
        });

        req.user = {
            userId: userData.userId,
            email: userData.email,
            accessToken: googleTokens.access_token,
            refreshToken: googleTokens.refresh_token
        };

        next();

    } catch (error) {
        console.error('❌ API key authentication error:', error);
        res.status(500).json({ error: 'Authentication service error' });
    }
}

// Debug configuration
console.log('🔧 Configuration Status:');
console.log('🌍 Environment:', process.env.NODE_ENV || 'development');
console.log('📍 Base URL:', BASE_URL);
console.log('🔗 Redirect URI:', REDIRECT_URI);
console.log('📍 Google OAuth configured:', !!(CLIENT_ID && CLIENT_SECRET));
console.log('🔥 Firebase configured:', !!process.env.FIREBASE_PROJECT_ID);
console.log('🔑 JWT Secret configured:', !!process.env.JWT_SECRET);

// Test encryption key
try {
    if (!ENCRYPTION_KEY) {
        throw new Error('ENCRYPTION_KEY is missing');
    }
    
    const key = Buffer.from(ENCRYPTION_KEY, 'base64');
    if (key.length !== 32) {
        throw new Error(`ENCRYPTION_KEY must be 32 bytes, got ${key.length} bytes`);
    }
    
    const testData = 'test-encryption';
    const encrypted = encrypt(testData);
    const decrypted = decrypt(encrypted);
    
    if (decrypted !== testData) {
        throw new Error('Encryption test failed');
    }
    
    console.log('✅ Encryption key valid and working');
} catch (error) {
    console.error('❌ ENCRYPTION_KEY ERROR:', error.message);
    const newKey = crypto.randomBytes(32).toString('base64');
    console.error('💡 Generate a new key:');
    console.error(`   ENCRYPTION_KEY=${newKey}`);
    process.exit(1);
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Check authentication status using JWT
app.get('/auth/status', (req, res) => {
    // Check for JWT token
    let token = null;
    
    if (req.headers.cookie) {
        const cookies = req.headers.cookie.split(';').reduce((acc, cookie) => {
            const [key, value] = cookie.trim().split('=');
            acc[key] = value;
            return acc;
        }, {});
        token = cookies['sheeter-auth'];
    }
    
    console.log('🔍 Auth Status Check:', {
        hasCookie: !!token,
        tokenPreview: token ? token.substring(0, 20) + '...' : 'none'
    });
    
    if (!token) {
        return res.json({
            authenticated: false,
            hasAccess: false,
            apiKey: null,
            userEmail: null
        });
    }
    
    const decoded = verifyUserToken(token);
    if (!decoded) {
        return res.json({
            authenticated: false,
            hasAccess: false,
            apiKey: null,
            userEmail: null
        });
    }
    
    console.log('✅ JWT token valid for user:', decoded.email);
    
    res.json({
        authenticated: true,
        hasAccess: true,
        apiKey: decoded.apiKey,
        userEmail: decoded.email
    });
});

// Start OAuth flow
app.get('/auth/google', (req, res) => {
    console.log('🔄 Starting OAuth flow...');

    const authUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: SCOPES,
        prompt: 'consent',
        include_granted_scopes: true
    });

    console.log('📋 Requesting scopes:', SCOPES);
    res.redirect(authUrl);
});

// Handle OAuth callback
app.get('/auth/callback', async (req, res) => {
    const { code, error } = req.query;

    console.log('🔄 OAuth callback received:', {
        hasCode: !!code,
        error: error
    });

    if (error) {
        console.error('❌ OAuth error:', error);
        return res.redirect('/?error=oauth_denied');
    }

    if (!code) {
        return res.redirect('/?error=no_code');
    }

    try {
        console.log('🔄 Exchanging code for tokens...');
        const { tokens } = await oauth2Client.getToken(code);

        const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        userOAuth2Client.setCredentials(tokens);

        const oauth2 = google.oauth2({ version: 'v2', auth: userOAuth2Client });
        const userInfo = await oauth2.userinfo.get();
        const userEmail = userInfo.data.email;

        if (!userEmail) {
            throw new Error('Failed to retrieve user email');
        }

        console.log(`✅ User authenticated: ${userEmail}`);

        const apiKey = await getOrCreateUserApiKey(userEmail, tokens);
        const userId = generateUserId(userEmail);

        // Generate JWT token
        const jwtToken = generateUserToken(userId, userEmail, apiKey);
        
        console.log('🎫 JWT token generated for user:', userEmail);

        // Set JWT as HTTP-only cookie
        res.cookie('sheeter-auth', jwtToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            path: '/'
        });

        console.log('🍪 Auth cookie set, redirecting to success');
        res.redirect('/?success=true');

    } catch (error) {
        console.error('❌ OAuth callback error:', error);
        res.redirect('/?error=oauth_failed');
    }
});

// Revoke access
app.post('/auth/revoke', authenticateJWT, async (req, res) => {
    try {
        const userEmail = req.user.email;
        console.log('🗑️ Revoking access for:', userEmail);

        // Delete from Firebase
        const userId = generateUserId(userEmail);
        await db.collection('user-credentials').doc(userId).delete();

        // Clear auth cookie
        res.clearCookie('sheeter-auth', { 
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/'
        });

        res.json({ 
            success: true, 
            message: 'Access revoked successfully' 
        });

    } catch (error) {
        console.error('❌ Revoke error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to revoke access' 
        });
    }
});

// Test JWT-based authentication
app.get('/api/test', authenticateJWT, async (req, res) => {
    try {
        // For testing, we need to get Google tokens from Firebase
        const userId = req.user.userId;
        const userRef = db.collection('user-credentials').doc(userId);
        const doc = await userRef.get();
        
        if (!doc.exists) {
            return res.status(404).json({ error: 'User credentials not found' });
        }
        
        const userData = doc.data();
        const googleTokens = JSON.parse(decrypt(userData.encryptedTokens));
        
        const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        userOAuth2Client.setCredentials({
            access_token: googleTokens.access_token,
            refresh_token: googleTokens.refresh_token
        });

        const sheets = google.sheets({ version: 'v4', auth: userOAuth2Client });
        const sheetId = '1lEwSquAnh7vNDUgk36isQio31Nc-JeBVBKtxXyjY8Vo';

        const metadataResponse = await sheets.spreadsheets.get({ 
            spreadsheetId: sheetId 
        });
        
        const dataResponse = await sheets.spreadsheets.values.get({
            spreadsheetId: sheetId,
            range: 'A1:Z10'
        });

        res.json({
            success: true,
            sheetName: metadataResponse.data.properties.title,
            sheetId: sheetId,
            rowCount: dataResponse.data.values?.length || 0,
            sampleData: dataResponse.data.values?.slice(0, 5) || [],
            message: 'JWT authentication test passed!',
            userEmail: req.user.email
        });

    } catch (error) {
        console.error('❌ JWT test failed:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Test API key access (unchanged)
app.get('/api/test-key', authenticateApiKey, async (req, res) => {
    try {
        const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        userOAuth2Client.setCredentials({
            access_token: req.user.accessToken,
            refresh_token: req.user.refreshToken
        });

        const sheets = google.sheets({ version: 'v4', auth: userOAuth2Client });
        const sheetId = '1lEwSquAnh7vNDUgk36isQio31Nc-JeBVBKtxXyjY8Vo';

        const metadataResponse = await sheets.spreadsheets.get({ 
            spreadsheetId: sheetId 
        });
        
        const dataResponse = await sheets.spreadsheets.values.get({
            spreadsheetId: sheetId,
            range: 'A1:Z10'
        });

        res.json({
            success: true,
            sheetName: metadataResponse.data.properties.title,
            sheetId: sheetId,
            rowCount: dataResponse.data.values?.length || 0,
            sampleData: dataResponse.data.values?.slice(0, 3) || [],
            message: 'API key authentication successful!',
            authenticatedAs: req.user.email
        });

    } catch (error) {
        console.error('❌ API Key test failed:', error);
        res.status(500).json({
            success: false,
            error: error.message,
            authenticatedAs: req.user.email
        });
    }
});

// All other Sheets API endpoints remain the same but use authenticateApiKey...

// Error handlers
app.use((err, req, res, next) => {
    console.error('❌ Server error:', err);
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🛑 Shutting down gracefully');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('🛑 Shutting down gracefully');  
    process.exit(0);
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Sheeter API running on port ${PORT}`);
    console.log('🔥 Using JWT-based authentication');
    console.log('Ready to handle requests!');
});