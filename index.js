require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(cors()); // Enable CORS
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

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

app.post('/oauth2/default/v1/token', (req, res, next) => {
  const { grant_type, client_id, client_secret, scope } = req.body;

  console.log('Token request received:', { grant_type, client_id, scope }); // Debug log

  if (grant_type !== 'client_credentials') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

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

  res.json({
    access_token: token,
    token_type: 'Bearer',
    expires_in: parseInt(process.env.TOKEN_EXPIRATION),
    scope: scope
  });
});

app.get('/stream/collections', verifyToken, (req, res, next) => {
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

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err); // Log error
  res.status(500).json({ error: 'Internal Server Error' });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
