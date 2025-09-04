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

/**
 * -----------------------------
 * Firebase Admin Initialization
 * -----------------------------
 */
const cleanFirebasePrivateKey = (k) =>
  (k || '')
    .replace(/\\n/g, '\n') // Render-style envs escape newlines
    .replace(/^"|"$/g, ''); // Strip accidental wrapping quotes

admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    privateKey: cleanFirebasePrivateKey(process.env.FIREBASE_PRIVATE_KEY),
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
  }),
  projectId: process.env.FIREBASE_PROJECT_ID,
});

const db = admin.firestore();

/**
 * -----------
 * Middleware
 * -----------
 */
app.use(express.json());
app.use(express.static('public'));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' },
  })
);

/**
 * ----------------------
 * Google OAuth Settings
 * ----------------------
 */
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const BASE_URL =
  process.env.NODE_ENV === 'production'
    ? process.env.BASE_URL || 'https://sheeter-lb5v.onrender.com'
    : `http://localhost:${PORT}`;
const REDIRECT_URI = `${BASE_URL}/auth/callback`;
const SCOPES = [
  'https://www.googleapis.com/auth/spreadsheets',
  'https://www.googleapis.com/auth/userinfo.email',
];

// Create OAuth2 client
const oauth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);

/**
 * ----------------------
 * Encryption Key Handling
 * ----------------------
 * Fixes: RangeError: Invalid key length (ERR_CRYPTO_INVALID_KEYLEN)
 * Accepts:
 *  - ENCRYPTION_SECRET starting with base64: or hex:
 *  - raw base64 or hex without prefix
 *  - any passphrase (derived with scrypt to 32 bytes)
 */
const deriveAes256Key = () => {
  const raw = process.env.ENCRYPTION_SECRET || process.env.ENCRYPTION_KEY || '';
  if (!raw) throw new Error('ENCRYPTION_SECRET (or ENCRYPTION_KEY) is required');

  const take = (buf) => {
    if (buf.length === 32) return buf; // perfect
    if (buf.length === 16) return Buffer.concat([buf, buf]); // upgrade 128->256 (dev-only convenience)
    return null;
  };

  let key = null;

  try {
    if (raw.startsWith('base64:')) key = take(Buffer.from(raw.slice(7), 'base64'));
    else if (raw.startsWith('hex:')) key = take(Buffer.from(raw.slice(4), 'hex'));
    else {
      // Try base64 then hex without prefixes
      key = take(Buffer.from(raw, 'base64')) || take(Buffer.from(raw, 'hex'));
    }
  } catch (_) {
    // ignore and derive instead
  }

  if (!key) {
    // Derive from passphrase deterministically (recommended when giving a plain secret)
    const salt = process.env.ENCRYPTION_SALT || 'sheeter-fixed-salt';
    key = crypto.scryptSync(raw, salt, 32);
  }

  if (key.length !== 32) {
    throw new Error(`Invalid encryption key length: ${key.length}. Expect 32 bytes for aes-256-cbc.`);
  }

  return key;
};

const AES_KEY = deriveAes256Key();

// Encryption helpers (stores iv alongside ciphertext)
function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', AES_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { encrypted, iv: iv.toString('hex') };
}

function decrypt(encryptedData) {
  const iv = Buffer.from(encryptedData.iv, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', AES_KEY, iv);
  let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * ---------------------
 * API Key + User Id util
 * ---------------------
 */
function generateApiKey() {
  return 'sk_' + crypto.randomBytes(32).toString('hex');
}

function generateUserId(email) {
  return crypto.createHash('sha256').update(email).digest('hex').substring(0, 16);
}

/**
 * -----------------------------
 * Create or Update user api key
 * -----------------------------
 */
async function getOrCreateUserApiKey(email, googleTokens) {
  const userId = generateUserId(email);
  const userRef = db.collection('user-credentials').doc(userId);

  try {
    const doc = await userRef.get();

    if (doc.exists) {
      const userData = doc.data();
      const encryptedTokens = encrypt(JSON.stringify(googleTokens));

      await userRef.update({
        encryptedTokens,
        lastAccess: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      console.log(`✅ Updated tokens for existing user: ${email}`);
      return userData.apiKey; // keep existing api key
    } else {
      const apiKey = generateApiKey();
      const apiKeyHash = await bcrypt.hash(apiKey, 12);
      const encryptedTokens = encrypt(JSON.stringify(googleTokens));

      await userRef.set({
        userId,
        email,
        apiKey, // NOTE: still stored in plaintext for lookup compatibility
        apiKeyHash,
        encryptedTokens,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        lastAccess: admin.firestore.FieldValue.serverTimestamp(),
      });

      console.log(`✅ Created new API key for user: ${email}`);
      return apiKey;
    }
  } catch (error) {
    console.error('❌ Firebase error:', error);
    throw error;
  }
}

/**
 * ---------------------
 * API Key Auth Middleware
 * ---------------------
 */
async function authenticateApiKey(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Missing or invalid authorization header. Use: Authorization: Bearer YOUR_API_KEY',
    });
  }

  const apiKey = authHeader.substring(7);

  try {
    const snapshot = await db
      .collection('user-credentials')
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
    await userDoc.ref.update({ lastAccess: admin.firestore.FieldValue.serverTimestamp() });

    // Attach to request (note refresh_token casing fixed)
    req.user = {
      userId: userData.userId,
      email: userData.email,
      accessToken: googleTokens.access_token,
      refreshToken: googleTokens.refresh_token,
      createdAt: userData.createdAt,
    };

    next();
  } catch (error) {
    console.error('❌ API key authentication error:', error);
    res.status(500).json({ error: 'Authentication service error' });
  }
}

/**
 * --------------------------
 * Startup Debug Information
 * --------------------------
 */
console.log('🔧 Configuration Status:');
console.log('📍 Google OAuth configured:', !!(CLIENT_ID && CLIENT_SECRET));
console.log('🔐 Encryption key ready (32 bytes):', AES_KEY.length === 32);
console.log('🔥 Firebase configured:', !!process.env.FIREBASE_PROJECT_ID);
console.log('🔗 Redirect URI:', REDIRECT_URI);

/**
 * -----------------
 * Basic HTTP routes
 * -----------------
 */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/auth/status', (req, res) => {
  const hasSession = !!req.session.accessToken;
  res.json({
    authenticated: hasSession,
    hasAccess: hasSession,
    apiKey: req.session.apiKey,
    userEmail: req.session.userEmail,
  });
});

// Start OAuth flow
app.get('/auth/google', (req, res) => {
  console.log('🔄 Starting OAuth flow...');
  const authUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: SCOPES,
    prompt: 'consent',
  });
  res.redirect(authUrl);
});

// OAuth callback
app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect('/?error=no_code');

  try {
    const { tokens } = await oauth2Client.getToken(code);

    const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    userOAuth2Client.setCredentials(tokens);

    const oauth2 = google.oauth2({ version: 'v2', auth: userOAuth2Client });
    const userInfo = await oauth2.userinfo.get();
    const userEmail = userInfo.data.email;

    console.log(`✅ User authenticated: ${userEmail}`);

    const apiKey = await getOrCreateUserApiKey(userEmail, tokens);

    // Session storage
    req.session.accessToken = tokens.access_token;
    req.session.refreshToken = tokens.refresh_token; // ensure correct casing
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

// Revoke access and delete stored credentials
app.post('/auth/revoke', async (req, res) => {
  const userEmail = req.session.userEmail;

  if (req.session.accessToken) {
    const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    userOAuth2Client.setCredentials({
      access_token: req.session.accessToken,
      refresh_token: req.session.refreshToken,
    });

    try {
      await userOAuth2Client.revokeCredentials();
    } catch (error) {
      console.log('⚠️ Token revocation failed (may already be invalid)');
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

  req.session.destroy(() => {});
  res.json({ success: true, message: 'Access revoked and API key deleted' });
});

// Session-based test
app.get('/api/test', async (req, res) => {
  if (!req.session.accessToken) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    userOAuth2Client.setCredentials({
      access_token: req.session.accessToken,
      refresh_token: req.session.refreshToken,
    });

    const sheets = google.sheets({ version: 'v4', auth: userOAuth2Client });
    const sheetId = '1lEwSquAnh7vNDUgk36isQio31Nc-JeBVBKtxXyjY8Vo';

    const metadataResponse = await sheets.spreadsheets.get({ spreadsheetId: sheetId });
    const dataResponse = await sheets.spreadsheets.values.get({ spreadsheetId: sheetId, range: 'A1:Z10' });

    res.json({
      success: true,
      sheetName: metadataResponse.data.properties.title,
      sheetId,
      rowCount: dataResponse.data.values?.length || 0,
      sampleData: dataResponse.data.values?.slice(0, 5) || [],
      message: 'Session access working!',
      apiKey: req.session.apiKey ? `${req.session.apiKey.substring(0, 20)}...` : null,
      userEmail: req.session.userEmail,
    });
  } catch (error) {
    console.error('❌ Session test failed:', error);
    res.status(500).json({ success: false, error: error.message, code: error.code });
  }
});

// API key test
app.get('/api/test-key', authenticateApiKey, async (req, res) => {
  try {
    const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    userOAuth2Client.setCredentials({
      access_token: req.user.accessToken,
      refresh_token: req.user.refreshToken,
    });

    const sheets = google.sheets({ version: 'v4', auth: userOAuth2Client });
    const sheetId = '1lEwSquAnh7vNDUgk36isQio31Nc-JeBVBKtxXyjY8Vo';

    const metadataResponse = await sheets.spreadsheets.get({ spreadsheetId: sheetId });
    const dataResponse = await sheets.spreadsheets.values.get({ spreadsheetId: sheetId, range: 'A1:Z10' });

    res.json({
      success: true,
      sheetName: metadataResponse.data.properties.title,
      sheetId,
      rowCount: dataResponse.data.values?.length || 0,
      sampleData: dataResponse.data.values?.slice(0, 3) || [],
      message: 'API key authentication successful!',
      authenticatedAs: req.user.email,
      keyCreated: req.user.createdAt,
    });
  } catch (error) {
    console.error('❌ API Key test failed:', error);
    res.status(500).json({ success: false, error: error.message, code: error.code, authenticatedAs: req.user.email });
  }
});

// Generic Sheets API endpoints (API key authenticated)
app.get('/api/sheets/:sheetId', authenticateApiKey, async (req, res) => {
  try {
    const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    userOAuth2Client.setCredentials({
      access_token: req.user.accessToken,
      refresh_token: req.user.refreshToken, // FIX: correct key name
    });

    const sheets = google.sheets({ version: 'v4', auth: userOAuth2Client });
    const { sheetId } = req.params;
    const { range = 'A:Z' } = req.query;

    const response = await sheets.spreadsheets.values.get({ spreadsheetId: sheetId, range });

    const rows = response.data.values || [];
    const headers = rows[0] || [];
    const data = rows.slice(1).map((row) => {
      const obj = {};
      headers.forEach((header, index) => {
        obj[header] = row[index] || '';
      });
      return obj;
    });

    res.json({ success: true, data, headers, rowCount: data.length, authenticatedAs: req.user.email });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, authenticatedAs: req.user.email });
  }
});

// Simple CRUD test endpoint
app.post('/api/test-write', authenticateApiKey, async (req, res) => {
  console.log('🧪 Testing CRUD write operation...');

  try {
    const userOAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    userOAuth2Client.setCredentials({
      access_token: req.user.accessToken,
      refresh_token: req.user.refreshToken,
    });

    const sheets = google.sheets({ version: 'v4', auth: userOAuth2Client });
    const sheetId = '1lEwSquAnh7vNDUgk36isQio31Nc-JeBVBKtxXyjY8Vo';

    console.log('✍️ Writing "Jo Mama" to A1...');

    const writeResponse = await sheets.spreadsheets.values.update({
      spreadsheetId: sheetId,
      range: 'A1',
      valueInputOption: 'USER_ENTERED',
      resource: { values: [['Jo Mama']] },
    });

    console.log('✅ Write successful:', writeResponse.data);

    res.json({
      success: true,
      message: 'CRUD write test successful!',
      updatedRange: writeResponse.data.updatedRange,
      updatedCells: writeResponse.data.updatedCells,
    });
  } catch (error) {
    console.error('❌ CRUD write test failed:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Sheeter API running on ${BASE_URL}`);
  console.log(`🔗 OAuth redirect URI: ${REDIRECT_URI}`);
  console.log('📋 Make sure to add this redirect URI to Google Console');
  console.log('🔥 Firebase configured:', !!process.env.FIREBASE_PROJECT_ID);
});
