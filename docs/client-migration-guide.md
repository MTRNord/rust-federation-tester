# Client Migration Guide: Magic Link to OAuth2

This guide explains how frontend clients can migrate from the legacy magic link authentication to the new OAuth2-based API.

## Overview

The Federation Tester supports two authentication methods:

| Method | API Version | Endpoints | Status |
|--------|-------------|-----------|--------|
| Magic Link | v1 | `/api/alerts/*` | Legacy (can be disabled) |
| OAuth2 | v2 | `/api/v2/alerts/*` | Recommended |

Once your frontend fully supports OAuth2, the legacy magic link API can be disabled server-side.

## API Endpoint Comparison

| Operation | Legacy (v1) | OAuth2 (v2) | Notes |
|-----------|-------------|-------------|-------|
| List alerts | `POST /api/alerts/list` + email verification | `GET /api/v2/alerts` | v2 returns immediately |
| Create alert | `POST /api/alerts/register` + email verification | `POST /api/v2/alerts` | v2 auto-verifies if email verified |
| Delete alert | `DELETE /api/alerts/{id}` + email verification | `DELETE /api/v2/alerts/{id}` | v2 deletes immediately |
| Verify email | `GET /api/alerts/verify?token=...` | Not needed | OAuth2 handles verification |

## OAuth2 Authentication Flow

### 1. Authorization Code Flow with PKCE

For web applications (SPAs), use the Authorization Code flow with PKCE:

```javascript
// 1. Generate PKCE code verifier and challenge
const codeVerifier = generateRandomString(64);
const codeChallenge = await sha256Base64Url(codeVerifier);

// 2. Redirect user to authorization endpoint
const authUrl = new URL('https://your-server/oauth2/authorize');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('redirect_uri', 'https://your-app/callback');
authUrl.searchParams.set('scope', 'openid email alerts:read alerts:write');
authUrl.searchParams.set('state', generateRandomString(32));
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');

window.location.href = authUrl.toString();
```

### 2. Handle Callback

```javascript
// User returns with authorization code
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const state = urlParams.get('state');

// Verify state matches what you sent
if (state !== savedState) {
  throw new Error('State mismatch - possible CSRF attack');
}

// 3. Exchange code for tokens
const tokenResponse = await fetch('https://your-server/oauth2/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: 'https://your-app/callback',
    client_id: 'your-client-id',
    code_verifier: codeVerifier,
  }),
});

const tokens = await tokenResponse.json();
// { access_token, refresh_token, expires_in, token_type, scope }
```

### 3. Store Tokens Securely

```javascript
// Store tokens securely (example using sessionStorage for SPAs)
sessionStorage.setItem('access_token', tokens.access_token);
sessionStorage.setItem('refresh_token', tokens.refresh_token);
sessionStorage.setItem('token_expires_at', Date.now() + tokens.expires_in * 1000);
```

## Using the v2 API

### Authentication Header

All v2 endpoints require a Bearer token:

```javascript
const headers = {
  'Authorization': `Bearer ${accessToken}`,
  'Content-Type': 'application/json',
};
```

### List Alerts

```javascript
const response = await fetch('https://your-server/api/v2/alerts', {
  headers: { 'Authorization': `Bearer ${accessToken}` },
});

const data = await response.json();
// { alerts: [...], total: number }
```

### Create Alert

```javascript
const response = await fetch('https://your-server/api/v2/alerts', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ server_name: 'matrix.example.com' }),
});

// 201 Created
const alert = await response.json();
// { id, server_name, verified, created_at }
```

### Delete Alert

```javascript
const response = await fetch(`https://your-server/api/v2/alerts/${alertId}`, {
  method: 'DELETE',
  headers: { 'Authorization': `Bearer ${accessToken}` },
});

// 204 No Content on success
```

## Token Refresh

Implement automatic token refresh before expiry:

```javascript
async function getValidAccessToken() {
  const expiresAt = parseInt(sessionStorage.getItem('token_expires_at'));
  const accessToken = sessionStorage.getItem('access_token');

  // Refresh if token expires in less than 5 minutes
  if (Date.now() > expiresAt - 5 * 60 * 1000) {
    const refreshToken = sessionStorage.getItem('refresh_token');

    const response = await fetch('https://your-server/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: 'your-client-id',
      }),
    });

    if (!response.ok) {
      // Refresh failed - user needs to re-authenticate
      throw new Error('Session expired');
    }

    const tokens = await response.json();
    sessionStorage.setItem('access_token', tokens.access_token);
    sessionStorage.setItem('token_expires_at', Date.now() + tokens.expires_in * 1000);
    if (tokens.refresh_token) {
      sessionStorage.setItem('refresh_token', tokens.refresh_token);
    }

    return tokens.access_token;
  }

  return accessToken;
}
```

## Handling 401 Errors

When receiving a 401 Unauthorized response:

```javascript
async function apiRequest(url, options = {}) {
  const accessToken = await getValidAccessToken();

  const response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${accessToken}`,
    },
  });

  if (response.status === 401) {
    // Token invalid - try refreshing once
    try {
      const newToken = await refreshToken();
      return fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${newToken}`,
        },
      });
    } catch {
      // Refresh failed - redirect to login
      window.location.href = '/login';
    }
  }

  return response;
}
```

## Required OAuth2 Scopes

| Scope | Description | Required For |
|-------|-------------|--------------|
| `openid` | OpenID Connect authentication | All requests |
| `email` | Access user's email address | Linking legacy alerts |
| `alerts:read` | View alert subscriptions | `GET /api/v2/alerts` |
| `alerts:write` | Create/delete alerts | `POST`, `DELETE /api/v2/alerts/*` |

Request all scopes during authorization:
```
scope=openid email alerts:read alerts:write
```

## Migration for Existing Users

### Automatic Alert Linking

When a user authenticates via OAuth2:

1. If their email is **verified** by the OAuth2 provider:
   - All legacy alerts (created via magic links) are automatically linked to their OAuth2 account
   - These alerts immediately appear in `GET /api/v2/alerts` responses

2. If their email is **not verified**:
   - Legacy alerts are NOT linked (security protection against account takeover)
   - User only sees alerts they create via the v2 API
   - Once email is verified, legacy alerts will be linked on next login

### Security: Email Verification Requirement

To prevent account takeover attacks, legacy alerts are only linked when:
- The OAuth2 provider confirms the user's email is verified, OR
- The user verifies their email through our email verification flow

This prevents an attacker from creating an OAuth2 account with someone else's email address and gaining access to their existing alerts.

## Detecting User Authentication State

```javascript
function isAuthenticated() {
  const accessToken = sessionStorage.getItem('access_token');
  const expiresAt = parseInt(sessionStorage.getItem('token_expires_at'));
  return accessToken && Date.now() < expiresAt;
}

function hasValidRefreshToken() {
  return !!sessionStorage.getItem('refresh_token');
}
```

## Logout

```javascript
async function logout() {
  const accessToken = sessionStorage.getItem('access_token');

  // Revoke token server-side (optional but recommended)
  if (accessToken) {
    await fetch('https://your-server/oauth2/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token: accessToken,
        token_type_hint: 'access_token',
      }),
    });
  }

  // Clear local storage
  sessionStorage.removeItem('access_token');
  sessionStorage.removeItem('refresh_token');
  sessionStorage.removeItem('token_expires_at');

  // Redirect to home or login page
  window.location.href = '/';
}
```

## Error Responses

The v2 API returns structured error responses:

```json
{
  "error": "error_code",
  "error_description": "Human-readable description"
}
```

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| `invalid_token` | 401 | Token missing, expired, or revoked |
| `insufficient_scope` | 403 | Token lacks required scope |
| `forbidden` | 403 | User doesn't own the resource |
| `not_found` | 404 | Alert doesn't exist |
| `alert_exists` | 400 | Duplicate alert for email+server |
| `bad_request` | 400 | Invalid request parameters |

## Client Registration

To use OAuth2, your application needs to be registered as a client. Contact the server administrator to register your application with:

- **Application name**: Display name shown to users
- **Redirect URIs**: Allowed callback URLs (e.g., `https://your-app.com/callback`)
- **Client type**: Public (SPA) or Confidential (server-side)

You'll receive:
- **Client ID**: Public identifier for your application
- **Client Secret**: (Confidential clients only) Keep this secure!

## Backward Compatibility

During the migration period:

1. **Both APIs work simultaneously** - Legacy and v2 endpoints are both available
2. **Alerts are shared** - Alerts created via either API are visible in both
3. **No data migration needed** - Legacy alerts are automatically linked when users authenticate via OAuth2

Once all users have migrated, the server administrator can disable the legacy API.
