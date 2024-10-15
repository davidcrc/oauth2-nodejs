require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');

const app = express();

// CORS configuration
const corsOptions = {
  origin: '*', // Allow all origins
  methods: ['GET', 'POST'], // Allow only GET and POST requests
  allowedHeaders: ['Content-Type', 'Authorization'], // Allow these headers
};

app.use(cors(corsOptions));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// In-memory storage for auth codes and PKCE code verifiers (replace with a database in production)
const authCodes = new Map();

// Simulated client verification
const verifyClient = (clientId, clientSecret) => {
  return clientId === process.env.CLIENT_ID && clientSecret === process.env.CLIENT_SECRET;
};

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  console.log('Received token:', token); // Debug log

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('Token verification error:', err); // Debug log
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          error: 'Token expired', 
          details: 'Please request a new token',
          expiredAt: err.expiredAt
        });
      }
      return res.status(403).json({ error: 'Failed to authenticate token', details: err.message });
    }
    req.decodedToken = decoded;
    console.log('Decoded token:', decoded); // Debug log
    next();
  });
};

// Helper function to generate a code challenge from a code verifier
const generateCodeChallenge = (codeVerifier) => {
  const base64Digest = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  return base64Digest;
};

// New endpoint for authorization
app.get('/oauth2/default/v1/authorize', (req, res) => {
  const { client_id, redirect_uri, code_challenge, code_challenge_method, state } = req.query;

  // Verify client_id and redirect_uri (implement your own logic)
  if (client_id !== process.env.CLIENT_ID) {
    return res.status(400).json({ error: 'invalid_client' });
  }

  // Generate an authorization code
  const authCode = crypto.randomBytes(16).toString('hex');

  // Store the auth code with the code challenge
  authCodes.set(authCode, { code_challenge, code_challenge_method });

  // Redirect back to the client with the auth code
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.append('code', authCode);
  if (state) {
    redirectUrl.searchParams.append('state', state);
  }

  res.redirect(redirectUrl.toString());
});

// Modified token endpoint to support both client credentials and authorization code with PKCE
app.post('/oauth2/default/v1/token', (req, res) => {
  const { grant_type, client_id, client_secret, code, code_verifier, redirect_uri, scope } = req.body;

  console.log('Token request received:', { grant_type, client_id, scope }); // Debug log

  if (grant_type === 'client_credentials') {
    if (!verifyClient(client_id, client_secret)) {
      return res.status(401).json({ error: 'invalid_client' });
    }

    if (scope !== 'client_token') {
      return res.status(400).json({ error: 'invalid_scope' });
    }

    const token = jwt.sign(
      { client_id, scope },
      process.env.JWT_SECRET,
      { expiresIn: parseInt(process.env.TOKEN_EXPIRATION) }
    );

    console.log('Generated token:', token); // Debug log
    console.log('Token expiration:', new Date(Date.now() + parseInt(process.env.TOKEN_EXPIRATION) * 1000).toISOString());

    return res.json({
      access_token: token,
      token_type: 'Bearer',
      expires_in: parseInt(process.env.TOKEN_EXPIRATION),
      scope: scope
    });
  } else if (grant_type === 'authorization_code') {
    // Verify the authorization code
    if (!authCodes.has(code)) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    const storedData = authCodes.get(code);
    authCodes.delete(code); // Remove the used code

    // Verify the code verifier
    const calculatedCodeChallenge = generateCodeChallenge(code_verifier);
    if (calculatedCodeChallenge !== storedData.code_challenge) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    // Generate the access token
    const token = jwt.sign(
      { client_id, scope: 'user_token' },
      process.env.JWT_SECRET,
      { expiresIn: parseInt(process.env.TOKEN_EXPIRATION) }
    );

    return res.json({
      access_token: token,
      token_type: 'Bearer',
      expires_in: parseInt(process.env.TOKEN_EXPIRATION),
      scope: 'user_token'
    });
  } else {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }
});

// New endpoint to simulate stream collections data
app.get('/stream/collections', verifyToken, (req, res) => {
  // Simulated data - replace with actual data retrieval logic
  const collections = [
    { id: 1, name: 'Collection 1' },
    { id: 2, name: 'Collection 2' },
    { id: 3, name: 'Collection 3' }
  ];

  res.json({
    collections: collections,
    client: req.decodedToken.client_id
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    message: err.message
  });
});

// 404 handler
app.use((req, res, next) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested resource was not found on this server.'
  });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));