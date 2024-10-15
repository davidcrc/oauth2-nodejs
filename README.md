# OAuth 2.0 Server with PKCE Support

This is a simple OAuth 2.0 server implementation using Node.js and Express. It supports both the Client Credentials flow and the Authorization Code flow with PKCE (Proof Key for Code Exchange).

## Features

- Client Credentials flow
- Authorization Code flow with PKCE
- JWT token generation and verification
- CORS support
- Basic error handling

## Prerequisites

- Node.js (v12 or higher)
- npm (Node Package Manager)

## Setup

1. Clone the repository or download the source code.

2. Install dependencies:

   ```
   npm install
   ```

3. Create a `.env` file in the root directory with the following content:

   ```
   PORT=3000
   JWT_SECRET=your_jwt_secret_here
   CLIENT_ID=your_client_id_here
   CLIENT_SECRET=your_client_secret_here
   TOKEN_EXPIRATION=3600
   ```

   Replace the values with your own secure secrets and desired configuration.

4. Start the server:
   ```
   npm run dev
   ```

## API Endpoints

### 1. Authorization Endpoint (for Authorization Code flow with PKCE)

- **URL**: `/oauth2/default/v1/authorize`
- **Method**: GET
- **Query Parameters**:
  - `client_id`: Your client ID
  - `redirect_uri`: The URI to redirect to after authorization
  - `code_challenge`: The PKCE code challenge
  - `code_challenge_method`: The method used to generate the code challenge (e.g., "S256")
  - `state` (optional): A value used to maintain state between the request and callback

### 2. Token Endpoint

- **URL**: `/oauth2/default/v1/token`
- **Method**: POST
- **Content-Type**: `application/x-www-form-urlencoded`
- **Body Parameters**:
  - For Client Credentials flow:
    - `grant_type`: "client_credentials"
    - `client_id`: Your client ID
    - `client_secret`: Your client secret
    - `scope`: "client_token"
  - For Authorization Code flow with PKCE:
    - `grant_type`: "authorization_code"
    - `code`: The authorization code received from the authorize endpoint
    - `code_verifier`: The PKCE code verifier
    - `redirect_uri`: The same redirect URI used in the authorization request

### 3. Protected Resource Endpoint (Example)

- **URL**: `/stream/collections`
- **Method**: GET
- **Headers**:
  - `Authorization`: Bearer {access_token}

## Usage Examples with Axios

First, install Axios in your project:

```bash
npm install axios
```

### Client Credentials Flow

```javascript
const axios = require("axios");

async function getClientCredentialsToken() {
  try {
    const response = await axios.post(
      "http://localhost:3000/oauth2/default/v1/token",
      new URLSearchParams({
        grant_type: "client_credentials",
        client_id: "your_client_id",
        client_secret: "your_client_secret",
        scope: "client_token",
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    console.log("Access Token:", response.data.access_token);
    return response.data.access_token;
  } catch (error) {
    console.error(
      "Error getting token:",
      error.response ? error.response.data : error.message
    );
  }
}

getClientCredentialsToken();
```

### Authorization Code Flow with PKCE

1. Generate a code verifier and code challenge:

```javascript
const crypto = require("crypto");

function generateCodeVerifier() {
  return crypto.randomBytes(32).toString("base64url");
}

function generateCodeChallenge(codeVerifier) {
  return crypto.createHash("sha256").update(codeVerifier).digest("base64url");
}

const codeVerifier = generateCodeVerifier();
const codeChallenge = generateCodeChallenge(codeVerifier);
```

2. Redirect the user to the authorization endpoint:

```javascript
const authUrl = new URL("http://localhost:3000/oauth2/default/v1/authorize");
authUrl.searchParams.append("client_id", "your_client_id");
authUrl.searchParams.append("redirect_uri", "http://localhost:8080/callback");
authUrl.searchParams.append("code_challenge", codeChallenge);
authUrl.searchParams.append("code_challenge_method", "S256");
authUrl.searchParams.append("state", "some_state_value");

console.log("Redirect the user to:", authUrl.toString());
// In a browser environment, you would use:
// window.location.href = authUrl.toString();
```

3. Exchange the authorization code for a token:

```javascript
const axios = require("axios");

async function exchangeCodeForToken(code) {
  try {
    const response = await axios.post(
      "http://localhost:3000/oauth2/default/v1/token",
      new URLSearchParams({
        grant_type: "authorization_code",
        code: code,
        code_verifier: codeVerifier,
        redirect_uri: "http://localhost:8080/callback",
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    console.log("Access Token:", response.data.access_token);
    return response.data.access_token;
  } catch (error) {
    console.error(
      "Error exchanging code for token:",
      error.response ? error.response.data : error.message
    );
  }
}

// Call this function with the received authorization code
// exchangeCodeForToken('received_authorization_code');
```

### Using the Access Token

Once you have the access token, you can use it to make authenticated requests:

```javascript
const axios = require("axios");

async function getProtectedResource(accessToken) {
  try {
    const response = await axios.get(
      "http://localhost:3000/stream/collections",
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );

    console.log("Protected Resource Data:", response.data);
  } catch (error) {
    console.error(
      "Error accessing protected resource:",
      error.response ? error.response.data : error.message
    );
  }
}

// Call this function with the access token
// getProtectedResource('your_access_token');
```

## Security Considerations

This is a basic implementation and should not be used in production without further security enhancements. Consider the following:

- Use HTTPS in production
- Implement rate limiting
- Add more robust error handling and logging
- Use a database for storing authorization codes and tokens
- Implement token revocation
- Add support for refresh tokens
- Implement proper user authentication for the authorization endpoint

## License

This project is open-source and available under the MIT License.
