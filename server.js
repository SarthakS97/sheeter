require('dotenv').config();
const express = require('express');
const path = require('path');
const { google } = require('googleapis');
const session = require('express-session');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
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

// Session configuration for production
const sessionConfig = {
    secret: process.env.SESSION_SECRET || 'your-session-secret-' + crypto.randomBytes(16).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        httpOnly: true
    }
};

// Add session store for production to avoid MemoryStore warning
if (process.env.NODE_ENV === 'production') {
    console.log('🔄 Using memory store for sessions (consider upgrading to Redis for production)');
}

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.use(session(sessionConfig));

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

// FIXED: Encryption functions using createCipheriv (NOT createCipher)
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
        console.log('🎲 Generated IV for encryption');
        
        // CRITICAL: Using createCipheriv (NOT createCipher)
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
        
        // CRITICAL: Using createDecipheriv (NOT createDecipher)
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

// Debug configuration on startup
console.log('🔧 Configuration Status:');
console.log('🌍 Environment:', process.env.NODE_ENV || 'development');
console.log('📍 Base URL:', BASE_URL);
console.log('🔗 Redirect URI:', REDIRECT_URI);
console.log('📍 Google OAuth configured:', !!(CLIENT_ID && CLIENT_SECRET));
console.log('🔥 Firebase configured:', !!process.env.FIREBASE_PROJECT_ID);

// Test encryption key
try {
    if (!ENCRYPTION_KEY) {
        throw new Error('ENCRYPTION_KEY is missing from environment variables');
    }
    
    console.log(`🔑 ENCRYPTION_KEY found: ${ENCRYPTION_KEY.length} characters`);
    
    const key = Buffer.from(ENCRYPTION_KEY, 'base64');
    console.log(`🔓 Decoded key length: ${key.length} bytes`);
    
    if (key.length !== 32) {
        throw new Error(`ENCRYPTION_KEY must be 32 bytes when decoded, got ${key.length} bytes`);
    }
    
    // Test encryption/decryption
    const testData = 'test-encryption';
    const encrypted = encrypt(testData);
    const decrypted = decrypt(encrypted);
    
    if (decrypted !== testData) {
        throw new Error('Encryption test failed');
    }
    
    console.log('✅ Encryption key is valid and working');
} catch (error) {
    console.error('❌ ENCRYPTION_KEY ERROR:', error.message);
    
    // Generate a new key for reference
    const newKey = crypto.randomBytes(32).toString('base64');
    console.error('💡 Fix by setting this key in your Render environment:');
    console.error(`   ENCRYPTION_KEY=${newKey}`);
    console.error('   The key should be exactly 44 characters long.');
    
    process.exit(1);
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

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/auth/status', (req, res) => {
    const hasSession = !!req.session.accessToken;
    res.json({
        authenticated: hasSession,
        hasAccess: hasSession,
        apiKey: req.session.apiKey,
        userEmail: req.session.userEmail
    });
});

app.get('/auth/google', (req, res) => {
    console.log('🔄 Starting OAuth flow...');
    const authUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: SCOPES,
        prompt: 'consent'
    });
    res.redirect(authUrl);
});

app.get('/auth/callback', async (req, res) => {
    const { code, error } = req.query;

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
            throw new Error('Failed to retrieve user email from Google');
        }

        console.log(`✅ User authenticated: ${userEmail}`);

        const apiKey = await getOrCreateUserApiKey(userEmail, tokens);

        req.session.accessToken = tokens.access_token;
        req.session.refreshToken = tokens.refresh_token;
        req.session.apiKey = apiKey;
        req.session.userEmail = userEmail;
        req.session.userId = generateUserId(userEmail);

        console.log(`✅ Session created for ${userEmail}`);
        res.redirect('/?success=true');

    } catch (error) {
        console.error('❌ OAuth callback error:', error);
        res.redirect('/?error=oauth_failed');
    }
});

app.post('/auth/revoke', async (req, res) => {
    const userEmail = req.session.userEmail;

    if (req.session.accessToken) {
        const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        userOAuth2Client.setCredentials({
            access_token: req.session.accessToken,
            refresh_token: req.session.refreshToken
        });

        try {
            await userOAuth2Client.revokeCredentials();
            console.log('✅ Google tokens revoked');
        } catch (error) {
            console.log('⚠️ Token revocation failed:', error.message);
        }
    }

    if (userEmail) {
        try {
            const userId = generateUserId(userEmail);
            await db.collection('user-credentials').doc(userId).delete();
            console.log(`🗑️ Deleted credentials for ${userEmail}`);
        } catch (error) {
            console.error('❌ Error deleting user credentials:', error);
        }
    }

    req.session.destroy((err) => {
        if (err) console.error('❌ Session destruction error:', err);
    });

    res.json({ success: true, message: 'Access revoked and API key deleted' });
});

// API Endpoints
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

        const metadataResponse = await sheets.spreadsheets.get({ spreadsheetId: sheetId });
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

app.get('/api/test-key', authenticateApiKey, async (req, res) => {
    try {
        const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        userOAuth2Client.setCredentials({
            access_token: req.user.accessToken,
            refresh_token: req.user.refreshToken
        });

        const sheets = google.sheets({ version: 'v4', auth: userOAuth2Client });
        const sheetId = '1lEwSquAnh7vNDUgk36isQio31Nc-JeBVBKtxXyjY8Vo';

        const metadataResponse = await sheets.spreadsheets.get({ spreadsheetId: sheetId });
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

// Sheets API endpoints
app.post('/api/sheets/create', authenticateApiKey, async (req, res) => {
    try {
        const { title } = req.body;
        if (!title) {
            return res.status(400).json({ error: 'Spreadsheet title is required.' });
        }

        const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        userOAuth2Client.setCredentials({
            access_token: req.user.accessToken,
            refresh_token: req.user.refreshToken
        });

        const sheets = google.sheets({ version: 'v4', auth: userOAuth2Client });
        const response = await sheets.spreadsheets.create({
            resource: { properties: { title } }
        });

        res.json({
            success: true,
            message: `Successfully created spreadsheet: "${title}"`,
            spreadsheetId: response.data.spreadsheetId,
            url: response.data.spreadsheetUrl
        });

    } catch (error) {
        console.error('❌ Create spreadsheet failed:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/sheets/:sheetId', authenticateApiKey, async (req, res) => {
    try {
        const { sheetId } = req.params;
        const { range = 'A:Z' } = req.query;

        const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        userOAuth2Client.setCredentials({
            access_token: req.user.accessToken,
            refresh_token: req.user.refreshToken
        });

        const sheets = google.sheets({ version: 'v4', auth: userOAuth2Client });
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
        console.error('❌ Read sheet failed:', error);
        res.status(500).json({
            success: false,
            error: error.message,
            authenticatedAs: req.user.email
        });
    }
});

app.post('/api/sheets/:sheetId/append', authenticateApiKey, async (req, res) => {
    try {
        const { sheetId } = req.params;
        const { values } = req.body;

        if (!values || !Array.isArray(values)) {
            return res.status(400).json({ error: 'Values must be a valid array of arrays.' });
        }

        const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        userOAuth2Client.setCredentials({
            access_token: req.user.accessToken,
            refresh_token: req.user.refreshToken
        });

        const sheets = google.sheets({ version: 'v4', auth: userOAuth2Client });
        const response = await sheets.spreadsheets.values.append({
            spreadsheetId: sheetId,
            range: 'A1',
            valueInputOption: 'USER_ENTERED',
            requestBody: { values }
        });

        res.json({
            success: true,
            message: 'Data successfully appended.',
            updates: response.data.updates
        });

    } catch (error) {
        console.error('❌ Append data failed:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.put('/api/sheets/:sheetId/values', authenticateApiKey, async (req, res) => {
    try {
        const { sheetId } = req.params;
        const { range, values } = req.body;

        if (!range || !values || !Array.isArray(values)) {
            return res.status(400).json({ error: 'Range and values (array of arrays) are required.' });
        }

        const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        userOAuth2Client.setCredentials({
            access_token: req.user.accessToken,
            refresh_token: req.user.refreshToken
        });

        const sheets = google.sheets({ version: 'v4', auth: userOAuth2Client });
        const response = await sheets.spreadsheets.values.update({
            spreadsheetId: sheetId,
            range: range,
            valueInputOption: 'USER_ENTERED',
            requestBody: { values }
        });

        res.json({
            success: true,
            message: `Successfully updated range "${response.data.updatedRange}"`,
            updatedRange: response.data.updatedRange,
            updatedCells: response.data.updatedCells
        });

    } catch (error) {
        console.error('❌ Update values failed:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/sheets/:sheetId/batch-update', authenticateApiKey, async (req, res) => {
    try {
        const { sheetId } = req.params;
        const { requests } = req.body;

        if (!requests || !Array.isArray(requests)) {
            return res.status(400).json({ error: 'Requests must be a valid array.' });
        }

        const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        userOAuth2Client.setCredentials({
            access_token: req.user.accessToken,
            refresh_token: req.user.refreshToken
        });

        const sheets = google.sheets({ version: 'v4', auth: userOAuth2Client });
        const response = await sheets.spreadsheets.batchUpdate({
            spreadsheetId: sheetId,
            requestBody: { requests }
        });

        res.json({
            success: true,
            message: 'Batch update successful.',
            replies: response.data.replies
        });

    } catch (error) {
        console.error('❌ Batch update failed:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.delete('/api/sheets/:sheetId/rows', authenticateApiKey, async (req, res) => {
    try {
        const { sheetId } = req.params;
        const { startIndex, endIndex, sheetTabId = 0 } = req.query;

        if (startIndex === undefined || endIndex === undefined) {
            return res.status(400).json({ 
                error: 'startIndex and endIndex query parameters are required.' 
            });
        }

        const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        userOAuth2Client.setCredentials({
            access_token: req.user.accessToken,
            refresh_token: req.user.refreshToken
        });

        const sheets = google.sheets({ version: 'v4', auth: userOAuth2Client });
        const request = {
            deleteDimension: {
                range: {
                    sheetId: parseInt(sheetTabId, 10),
                    dimension: 'ROWS',
                    startIndex: parseInt(startIndex, 10),
                    endIndex: parseInt(endIndex, 10)
                }
            }
        };

        const response = await sheets.spreadsheets.batchUpdate({
            spreadsheetId: sheetId,
            requestBody: { requests: [request] }
        });

        res.json({
            success: true,
            message: `Successfully deleted rows from index ${startIndex} to ${endIndex}.`,
            replies: response.data.replies
        });

    } catch (error) {
        console.error('❌ Delete rows failed:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

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
    console.log('🛑 SIGTERM received, shutting down gracefully');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('🛑 SIGINT received, shutting down gracefully');
    process.exit(0);
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Sheeter API running on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log('🔥 Ready to handle requests!');
});