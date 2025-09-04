require('dotenv').config();
const express = require('express');
const path = require('path');
const { google } = require('googleapis');
const session = require('express-session');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const admin = require('firebase-admin');

const app = express();
const PORT = 3000;

// Initialize Firebase Admin
admin.initializeApp({
    credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    }),
    projectId: process.env.FIREBASE_PROJECT_ID
});

const db = admin.firestore();

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret-' + Math.random(),
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true in production with HTTPS
}));

// Google OAuth Configuration
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const BASE_URL = process.env.NODE_ENV === 'production' 
    ? 'https://sheeter-lb5v.onrender.com' 
    : `http://localhost:${PORT}`;
const REDIRECT_URI = `${BASE_URL}/auth/callback`;
const SCOPES = ['https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/userinfo.email'];
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// Create OAuth2 client
const oauth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);

// Encryption functions
function encrypt(text) {
    const key = Buffer.from(ENCRYPTION_KEY, 'base64');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher('aes-256-cbc', key);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return {
        encrypted,
        iv: iv.toString('hex')
    };
}

function decrypt(encryptedData) {
    const key = Buffer.from(ENCRYPTION_KEY, 'base64');
    const decipher = crypto.createDecipher('aes-256-cbc', key);
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
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
            // User exists, update tokens but keep same API key
            const userData = doc.data();
            
            // Encrypt new tokens
            const encryptedTokens = encrypt(JSON.stringify(googleTokens));
            
            await userRef.update({
                encryptedTokens: encryptedTokens,
                lastAccess: admin.firestore.FieldValue.serverTimestamp(),
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            });
            
            console.log(`✅ Updated tokens for existing user: ${email}`);
            return userData.apiKey; // Return existing API key
            
        } else {
            // New user, create new API key
            const apiKey = generateApiKey();
            const apiKeyHash = await bcrypt.hash(apiKey, 12);
            const encryptedTokens = encrypt(JSON.stringify(googleTokens));
            
            await userRef.set({
                userId: userId,
                email: email,
                apiKey: apiKey, // Store plaintext for now, will hash in production
                apiKeyHash: apiKeyHash,
                encryptedTokens: encryptedTokens,
                createdAt: admin.firestore.FieldValue.serverTimestamp(),
                lastAccess: admin.firestore.FieldValue.serverTimestamp()
            });
            
            console.log(`✅ Created new API key for user: ${email}`);
            return apiKey; // Return new API key
        }
        
    } catch (error) {
        console.error('❌ Firebase error:', error);
        throw error;
    }
}

// Authenticate API key
async function authenticateApiKey(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ 
            error: 'Missing or invalid authorization header. Use: Authorization: Bearer YOUR_API_KEY' 
        });
    }
    
    const apiKey = authHeader.substring(7);
    
    try {
        // Query Firestore for the API key
        const snapshot = await db.collection('user-credentials')
            .where('apiKey', '==', apiKey)
            .limit(1)
            .get();
        
        if (snapshot.empty) {
            return res.status(401).json({ error: 'Invalid API key' });
        }
        
        const userDoc = snapshot.docs[0];
        const userData = userDoc.data();
        
        // Decrypt Google tokens
        const googleTokens = JSON.parse(decrypt(userData.encryptedTokens));
        
        // Update last access time
        await userDoc.ref.update({
            lastAccess: admin.firestore.FieldValue.serverTimestamp()
        });
        
        // Attach user data to request
        req.user = {
            userId: userData.userId,
            email: userData.email,
            accessToken: googleTokens.access_token,
            refreshToken: googleTokens.refresh_token,
            createdAt: userData.createdAt
        };
        
        next();
        
    } catch (error) {
        console.error('❌ API key authentication error:', error);
        res.status(500).json({ error: 'Authentication service error' });
    }
}

// Debug configuration on startup
console.log('🔧 Configuration Status:');
console.log('📍 Google OAuth configured:', !!(CLIENT_ID && CLIENT_SECRET));
console.log('🔐 Encryption configured:', !!ENCRYPTION_KEY);
console.log('🔥 Firebase configured:', !!process.env.FIREBASE_PROJECT_ID);
console.log('🔗 Redirect URI:', REDIRECT_URI);

// Serve main HTML page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Check authentication status
app.get('/auth/status', (req, res) => {
    const hasSession = !!req.session.accessToken;
    const apiKey = req.session.apiKey;
    const userEmail = req.session.userEmail;
    
    res.json({ 
        authenticated: hasSession,
        hasAccess: hasSession,
        apiKey: apiKey,
        userEmail: userEmail
    });
});

// Start OAuth flow
app.get('/auth/google', (req, res) => {
    console.log('🔄 Starting OAuth flow...');
    
    const authUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: SCOPES,
        prompt: 'consent'
    });
    
    res.redirect(authUrl);
});

// Handle OAuth callback
app.get('/auth/callback', async (req, res) => {
    const { code } = req.query;
    
    if (!code) {
        return res.redirect('/?error=no_code');
    }

    try {
        // Exchange code for tokens
        const { tokens } = await oauth2Client.getToken(code);
        
        // Create authenticated client to get user info
        const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        userOAuth2Client.setCredentials(tokens);
        
        const oauth2 = google.oauth2({ version: 'v2', auth: userOAuth2Client });
        const userInfo = await oauth2.userinfo.get();
        const userEmail = userInfo.data.email;

        console.log(`✅ User authenticated: ${userEmail}`);

        // Get or create API key for this user (replaces old key if exists)
        const apiKey = await getOrCreateUserApiKey(userEmail, tokens);

        // Store in session
        req.session.accessToken = tokens.access_token;
        req.session.refreshToken = tokens.refresh_token;
        req.session.apiKey = apiKey;
        req.session.userEmail = userEmail;
        req.session.userId = generateUserId(userEmail);
        
        console.log(`✅ API key ready for ${userEmail}: ${apiKey.substring(0, 20)}...`);
        res.redirect('/?success=true');
        
    } catch (error) {
        console.error('❌ OAuth callback error:', error);
        res.redirect('/?error=oauth_failed');
    }
});

// Revoke access
app.post('/auth/revoke', async (req, res) => {
    const userEmail = req.session.userEmail;
    
    if (req.session.accessToken) {
        // Revoke Google token
        const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        userOAuth2Client.setCredentials({
            access_token: req.session.accessToken,
            refresh_token: req.session.refreshToken
        });
        
        try {
            await userOAuth2Client.revokeCredentials();
        } catch (error) {
            console.log('⚠️ Token revocation failed (may already be invalid)');
        }
    }
    
    // Delete user credentials from Firebase
    if (userEmail) {
        try {
            const userId = generateUserId(userEmail);
            await db.collection('user-credentials').doc(userId).delete();
            console.log(`🗑️ Deleted credentials for ${userEmail}`);
        } catch (error) {
            console.error('❌ Error deleting user credentials:', error);
        }
    }
    
    // Clear session
    req.session.destroy();
    
    res.json({ success: true, message: 'Access revoked and API key deleted' });
});

// Test Google Sheets access (session-based)
app.get('/api/test', async (req, res) => {
    if (!req.session.accessToken) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        userOAuth2Client.setCredentials({
            access_token: req.session.accessToken,
            refresh_token: req.session.refreshToken
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
            message: 'Session access working!',
            apiKey: req.session.apiKey ? `${req.session.apiKey.substring(0, 20)}...` : null,
            userEmail: req.session.userEmail
        });

    } catch (error) {
        console.error('❌ Session test failed:', error);
        res.status(500).json({
            success: false,
            error: error.message,
            code: error.code
        });
    }
});

// Test API key access (what MCP will use)
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
            message: `API key authentication successful!`,
            authenticatedAs: req.user.email,
            keyCreated: req.user.createdAt
        });

    } catch (error) {
        console.error('❌ API Key test failed:', error);
        res.status(500).json({
            success: false,
            error: error.message,
            code: error.code,
            authenticatedAs: req.user.email
        });
    }
});

// Generic Sheets API endpoints (API key authenticated)
app.get('/api/sheets/:sheetId', authenticateApiKey, async (req, res) => {
    try {
        const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        userOAuth2Client.setCredentials({
            access_token: req.user.accessToken,
            refresh_token: req.user.refreshToken
        });

        const sheets = google.sheets({ version: 'v4', auth: userOAuth2Client });
        const { sheetId } = req.params;
        const { range = 'A:Z' } = req.query;

        const response = await sheets.spreadsheets.values.get({
            spreadsheetId: sheetId,
            range: range
        });

        const rows = response.data.values || [];
        const headers = rows[0] || [];
        const data = rows.slice(1).map(row => {
            const obj = {};
            headers.forEach((header, index) => {
                obj[header] = row[index] || '';
            });
            return obj;
        });

        res.json({ 
            success: true, 
            data, 
            headers, 
            rowCount: data.length,
            authenticatedAs: req.user.email
        });

    } catch (error) {
        res.status(500).json({ 
            success: false, 
            error: error.message,
            authenticatedAs: req.user.email
        });
    }
});

// Simple CRUD test endpoint
app.post('/api/test-write', authenticateApiKey, async (req, res) => {
    console.log('🧪 Testing CRUD write operation...');
    
    try {
        const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        userOAuth2Client.setCredentials({
            access_token: req.user.accessToken,
            refresh_token: req.user.refreshToken
        });

        const sheets = google.sheets({ version: 'v4', auth: userOAuth2Client });
        const sheetId = '1lEwSquAnh7vNDUgk36isQio31Nc-JeBVBKtxXyjY8Vo';
        
        console.log('✍️ Writing "Jo Mama" to A1...');
        
        const writeResponse = await sheets.spreadsheets.values.update({
            spreadsheetId: sheetId,
            range: 'A1',
            valueInputOption: 'USER_ENTERED',
            resource: {
                values: [['Jo Mama']]
            }
        });
        
        console.log('✅ Write successful:', writeResponse.data);
        
        res.json({
            success: true,
            message: 'CRUD write test successful!',
            updatedRange: writeResponse.data.updatedRange,
            updatedCells: writeResponse.data.updatedCells
        });
        
    } catch (error) {
        console.error('❌ CRUD write test failed:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Sheeter API running on http://localhost:${PORT}`);
    console.log(`🔗 OAuth redirect URI: ${REDIRECT_URI}`);
    console.log('📋 Make sure to add this redirect URI to Google Console');
    console.log('🔥 Firebase configured:', !!process.env.FIREBASE_PROJECT_ID);
});