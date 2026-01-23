# OAuth2 Setup Guide

This guide explains how to configure and use the OAuth2 authorization server for the Matrix Federation Tester.

## Architecture Overview

The federation tester acts as its own OAuth2 authorization server (similar to how Keycloak works). The frontend authenticates exclusively through this server's OAuth2 endpoints.

```
┌─────────────────┐     ┌─────────────────────────┐
│                 │     │   Federation Tester     │
│    Frontend     │────▶│   API Server            │
│   (SPA/Web)     │     │   (OAuth2 Provider)     │
│                 │     │                         │
└─────────────────┘     └─────────────────────────┘
        │                          │
        │  OAuth2 Flow             │  Database
        │  (Authorization Code     │  (Clients, Users,
        │   + PKCE)                │   Tokens)
        ▼                          ▼
```

## Configuration

### Understanding `issuer_url`

The `issuer_url` is the **public URL where the API server is reachable** (not the frontend URL). This is used in:
- The OpenID Connect discovery document (`/.well-known/openid-configuration`)
- Token validation
- Building endpoint URLs in responses

**Important:** The API can be hosted:
- On a different domain than the frontend (e.g., `api.example.com` vs `app.example.com`)
- On a subpath of the same domain (e.g., `example.com/api`)
- On the same domain with different ports during development

### Example Configurations

#### Same domain, API at root
```yaml
frontend_url: "https://federation-tester.example.com"
oauth2:
  enabled: true
  issuer_url: "https://federation-tester.example.com"
```

#### API on subdomain
```yaml
frontend_url: "https://app.federation-tester.example.com"
oauth2:
  enabled: true
  issuer_url: "https://api.federation-tester.example.com"
```

#### API at subpath (reverse proxy setup)
```yaml
frontend_url: "https://federation-tester.example.com"
oauth2:
  enabled: true
  issuer_url: "https://federation-tester.example.com/api"
```

#### Local development
```yaml
frontend_url: "http://localhost:3000"
oauth2:
  enabled: true
  issuer_url: "http://localhost:8080"
```

## Client Registration

OAuth2 clients must be registered in the database before they can authenticate users. Currently, this is done via SQL (no admin API yet).

### Registering a Frontend Client (Public Client)

For single-page applications (SPAs), use a **public client** (no secret):

```sql
INSERT INTO oauth2_client (
    id,
    secret,
    name,
    redirect_uris,
    grant_types,
    scopes,
    is_public,
    created_at,
    updated_at
) VALUES (
    'federation-tester-frontend',           -- client_id (used in OAuth2 requests)
    NULL,                                    -- no secret for public clients
    'Federation Tester Frontend',            -- human-readable name
    '["https://app.example.com/callback", "https://app.example.com/silent-refresh"]',  -- JSON array of allowed redirect URIs
    'authorization_code refresh_token',      -- space-separated grant types
    'openid profile email',                  -- space-separated allowed scopes
    true,                                    -- is_public = true for SPAs
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);
```

### Registering a Confidential Client (Backend/Server)

For server-side applications that can keep secrets:

```sql
INSERT INTO oauth2_client (
    id,
    secret,
    name,
    redirect_uris,
    grant_types,
    scopes,
    is_public,
    created_at,
    updated_at
) VALUES (
    'my-backend-service',
    'your-secure-secret-here',              -- store securely!
    'Backend Service',
    '["https://backend.example.com/oauth/callback"]',
    'authorization_code refresh_token',
    'openid email',
    false,                                   -- is_public = false (requires secret)
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);
```

### Field Reference

| Field | Description |
|-------|-------------|
| `id` | Client identifier, used as `client_id` in OAuth2 requests |
| `secret` | Client secret for confidential clients, NULL for public clients |
| `name` | Human-readable name (for admin/logging purposes) |
| `redirect_uris` | JSON array of allowed redirect URIs |
| `grant_types` | Space-separated list: `authorization_code`, `refresh_token` |
| `scopes` | Space-separated list of allowed scopes |
| `is_public` | `true` for SPAs/mobile apps, `false` for backend services |

## OAuth2 Endpoints

Once configured, the following endpoints are available:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OpenID Connect Discovery |
| `/oauth2/authorize` | GET | Authorization endpoint |
| `/oauth2/token` | POST | Token endpoint |
| `/oauth2/revoke` | POST | Token revocation (RFC 7009) |
| `/oauth2/userinfo` | GET | OpenID Connect UserInfo |

## Frontend Integration

### 1. Discovery

Fetch the OpenID Configuration to get endpoint URLs:

```javascript
const config = await fetch(`${API_URL}/.well-known/openid-configuration`)
  .then(r => r.json());

// config.authorization_endpoint = "https://api.example.com/oauth2/authorize"
// config.token_endpoint = "https://api.example.com/oauth2/token"
// etc.
```

### 2. Authorization Request (with PKCE)

Generate PKCE challenge and redirect user:

```javascript
// Generate PKCE verifier and challenge
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64URLEncode(array);
}

async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64URLEncode(new Uint8Array(digest));
}

// Store verifier for later
const codeVerifier = generateCodeVerifier();
sessionStorage.setItem('code_verifier', codeVerifier);

const codeChallenge = await generateCodeChallenge(codeVerifier);

// Build authorization URL
const params = new URLSearchParams({
  response_type: 'code',
  client_id: 'federation-tester-frontend',
  redirect_uri: 'https://app.example.com/callback',
  scope: 'openid profile email',
  state: crypto.randomUUID(),  // CSRF protection
  code_challenge: codeChallenge,
  code_challenge_method: 'S256',
  // Optional: pre-fill email field
  login_hint: 'user@example.com',
});

window.location.href = `${config.authorization_endpoint}?${params}`;
```

### 3. Token Exchange

After the user authenticates, exchange the code for tokens:

```javascript
// In your callback handler
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const codeVerifier = sessionStorage.getItem('code_verifier');

const response = await fetch(config.token_endpoint, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    client_id: 'federation-tester-frontend',
    redirect_uri: 'https://app.example.com/callback',
    code_verifier: codeVerifier,
  }),
});

const tokens = await response.json();
// {
//   access_token: "...",
//   refresh_token: "...",
//   token_type: "Bearer",
//   expires_in: 3600,
//   scope: "openid profile email"
// }
```

### 4. Using the Access Token

Include the access token in API requests:

```javascript
const response = await fetch(`${API_URL}/api/alerts`, {
  headers: {
    'Authorization': `Bearer ${tokens.access_token}`,
  },
});
```

### 5. Refreshing Tokens

Before the access token expires, use the refresh token:

```javascript
const response = await fetch(config.token_endpoint, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: tokens.refresh_token,
    client_id: 'federation-tester-frontend',
  }),
});

const newTokens = await response.json();
```

### 6. Getting User Info

Fetch the authenticated user's profile:

```javascript
const userInfo = await fetch(config.userinfo_endpoint, {
  headers: {
    'Authorization': `Bearer ${tokens.access_token}`,
  },
}).then(r => r.json());

// {
//   sub: "user-uuid",
//   email: "user@example.com",
//   email_verified: true,
//   name: "User Name"  // if profile scope was granted
// }
```

## Security Considerations

### For Public Clients (SPAs)

1. **Always use PKCE** - Required for public clients to prevent authorization code interception
2. **Use short-lived access tokens** - Default is 1 hour
3. **Store tokens securely** - Use `sessionStorage` or secure cookies, never `localStorage`
4. **Validate `state` parameter** - Prevents CSRF attacks

### For Confidential Clients

1. **Protect the client secret** - Never expose in client-side code
2. **Use Basic auth for token requests** - `Authorization: Basic base64(client_id:client_secret)`
3. **Rotate secrets periodically** - Update the database when rotating

### Redirect URI Validation

The server strictly validates redirect URIs:
- Must exactly match one of the registered URIs
- No wildcards or pattern matching
- Register all environments (dev, staging, prod) separately

## Migration from Magic Links

If you have existing users using magic link authentication:

1. **Both systems work in parallel** - Set `magic_links_enabled: true`
2. **Existing alerts remain functional** - No immediate migration required
3. **User accounts are linked by email** - When a user authenticates via OAuth2, their existing alerts are automatically associated

To disable magic links after migration:
```yaml
oauth2:
  enabled: true
  magic_links_enabled: false  # Force OAuth2 for all users
```

## Troubleshooting

### "invalid_client" error
- Verify the `client_id` exists in the database
- For confidential clients, check the secret is correct

### "invalid_redirect_uri" error
- The redirect URI must exactly match one in `redirect_uris` JSON array
- Check for trailing slashes, http vs https, port numbers

### Discovery document returns wrong URLs
- Verify `issuer_url` in config matches your actual API URL
- If behind a reverse proxy, ensure the proxy preserves the host header

### PKCE verification failed
- Ensure `code_verifier` is stored and retrieved correctly
- Verify SHA-256 hashing and base64url encoding are correct
