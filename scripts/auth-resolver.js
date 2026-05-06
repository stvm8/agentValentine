#!/usr/bin/env node
/**
 * auth-resolver.js
 *
 * Reads a swagger file, detects the authentication scheme,
 * attempts to acquire tokens automatically, and writes them
 * into the environment file so Newman can use them.
 *
 * Supported schemes (auto-detected):
 *   - Bearer token via login endpoint (POST with username/password or email/password)
 *   - API key in header
 *   - Custom header token (Authorization-Token pattern — vAPI style)
 *   - Basic auth
 *
 * Usage:
 *   node auth-resolver.js \
 *     --swagger ./swagger.json \
 *     --env ./generated/collection.environment.json \
 *     --credentials ./credentials.json
 */

const fs   = require('fs');
const path = require('path');

const args    = process.argv.slice(2);
const getArg  = (f) => { const i = args.indexOf(f); return i !== -1 ? args[i+1] : null; };

const SWAGGER_PATH  = getArg('--swagger')     || './swagger.json';
const ENV_PATH      = getArg('--env')         || './generated/collection.environment.json';
const CREDS_PATH    = getArg('--credentials') || './credentials.json';

// ─── Load inputs ──────────────────────────────────────────────────────────────

if (!fs.existsSync(SWAGGER_PATH)) {
  console.error(`ERROR: Swagger not found: ${SWAGGER_PATH}`); process.exit(1);
}
if (!fs.existsSync(ENV_PATH)) {
  console.error(`ERROR: Environment file not found: ${ENV_PATH}\nRun generate-collection.js first.`);
  process.exit(1);
}

const swagger     = JSON.parse(fs.readFileSync(SWAGGER_PATH, 'utf8'));
const environment = JSON.parse(fs.readFileSync(ENV_PATH, 'utf8'));
const credentials = fs.existsSync(CREDS_PATH)
  ? JSON.parse(fs.readFileSync(CREDS_PATH, 'utf8'))
  : {};

const BASE_URL = (environment.values.find(v => v.key === 'base_url') || {}).value
              || process.env.TARGET_URL
              || 'http://localhost:8081';

// ─── Step 1: Detect auth scheme from swagger ──────────────────────────────────

function detectAuthScheme(swagger) {
  const schemes = [];

  // Check securitySchemes
  const securitySchemes = swagger.components?.securitySchemes || {};
  for (const [name, scheme] of Object.entries(securitySchemes)) {
    if (scheme.type === 'http' && scheme.scheme === 'bearer') {
      schemes.push({ type: 'bearer', name });
    } else if (scheme.type === 'apiKey') {
      schemes.push({ type: 'apiKey', name, in: scheme.in, headerName: scheme.name });
    } else if (scheme.type === 'http' && scheme.scheme === 'basic') {
      schemes.push({ type: 'basic', name });
    }
  }

  // Scan endpoints for custom header patterns (e.g. vAPI's Authorization-Token)
  const customTokenHeaders = new Set();
  for (const pathItem of Object.values(swagger.paths || {})) {
    for (const op of Object.values(pathItem)) {
      for (const param of (op.parameters || [])) {
        if (param.in === 'header') {
          const n = param.name.toLowerCase();
          if (n.includes('authorization') || n.includes('token') || n.includes('x-api-key')) {
            customTokenHeaders.add(param.name);
          }
        }
      }
    }
  }

  if (customTokenHeaders.size > 0 && schemes.length === 0) {
    schemes.push({ type: 'customHeader', headers: [...customTokenHeaders] });
  }

  return schemes;
}

// ─── Step 2: Find login endpoints in the swagger ──────────────────────────────

function findLoginEndpoints(swagger) {
  const loginEndpoints = [];

  for (const [endpointPath, pathItem] of Object.entries(swagger.paths || {})) {
    for (const [method, op] of Object.entries(pathItem)) {
      if (!['post', 'get'].includes(method)) continue;

      const isLogin = /login|auth|token|signin|sign-in/i.test(endpointPath) ||
                      /login|auth|token|signin/i.test(op.summary || '');

      if (!isLogin) continue;

      // Extract the body fields from the example
      const bodyExample = op.requestBody?.content?.['application/json']?.schema?.example || {};
      const bodyFields = Object.keys(bodyExample);

      loginEndpoints.push({
        method: method.toUpperCase(),
        path: endpointPath,
        summary: op.summary || '',
        bodyFields,
        bodyExample,
        tags: op.tags || []
      });
    }
  }

  return loginEndpoints;
}

// ─── Step 3: Attempt token acquisition ───────────────────────────────────────

async function acquireToken(loginEndpoint, creds) {
  const url = BASE_URL + loginEndpoint.path;

  // Build request body from credentials + swagger example as template
  const body = { ...loginEndpoint.bodyExample };

  // Map credential fields — try common field name variations
  const fieldMappings = {
    username:  ['username', 'user', 'login', 'email'],
    password:  ['password', 'pass', 'pwd', 'secret'],
    email:     ['email', 'username', 'user'],
    pin:       ['pin', 'otp', 'code'],
    mobileno:  ['mobileno', 'mobile', 'phone', 'phoneno']
  };

  for (const [bodyField] of Object.entries(body)) {
    const lf = bodyField.toLowerCase();
    for (const [credKey, aliases] of Object.entries(fieldMappings)) {
      if (aliases.includes(lf) && creds[credKey]) {
        body[bodyField] = creds[credKey];
        break;
      }
    }
    // Also try direct match from credentials
    if (creds[bodyField]) body[bodyField] = creds[bodyField];
  }

  console.log(`  Attempting login: ${loginEndpoint.method} ${url}`);
  console.log(`  Body fields: ${Object.keys(body).join(', ')}`);

  try {
    const response = await fetch(url, {
      method: loginEndpoint.method,
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: loginEndpoint.method !== 'GET' ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(10000)
    });

    const responseText = await response.text();
    let responseBody;
    try { responseBody = JSON.parse(responseText); } catch { responseBody = {}; }

    console.log(`  Response: ${response.status}`);

    if (!response.ok && response.status !== 200) {
      return { success: false, status: response.status, body: responseBody };
    }

    // Extract token from response — try common token field names
    const tokenFields = ['token', 'access_token', 'accessToken', 'jwt',
                         'Authorization', 'auth_token', 'bearer', 'key'];
    let token = null;
    let tokenField = null;

    for (const field of tokenFields) {
      if (responseBody[field]) {
        token = responseBody[field];
        tokenField = field;
        break;
      }
      // Check nested: { data: { token: ... } } or { user: { token: ... } }
      for (const nested of Object.values(responseBody)) {
        if (typeof nested === 'object' && nested?.[field]) {
          token = nested[field];
          tokenField = `(nested).${field}`;
          break;
        }
      }
      if (token) break;
    }

    // Also try response headers
    const authHeader = response.headers.get('authorization') ||
                       response.headers.get('authorization-token') ||
                       response.headers.get('x-auth-token');
    if (!token && authHeader) {
      token = authHeader.replace(/^Bearer\s+/i, '');
      tokenField = 'response-header';
    }

    return {
      success: !!token,
      status: response.status,
      token,
      tokenField,
      userId: responseBody.id || responseBody.user_id || responseBody.userId || null,
      fullBody: responseBody
    };

  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Step 4: Write tokens into environment file ───────────────────────────────

function updateEnvironment(envPath, updates) {
  const env = JSON.parse(fs.readFileSync(envPath, 'utf8'));

  for (const [key, value] of Object.entries(updates)) {
    const existing = env.values.find(v => v.key === key);
    if (existing) {
      existing.value = value;
    } else {
      env.values.push({ key, value, enabled: true });
    }
  }

  fs.writeFileSync(envPath, JSON.stringify(env, null, 2));
  console.log(`\n  Environment updated: ${envPath}`);
}

// ─── Step 5: Print what needs manual intervention ────────────────────────────

function printManualInstructions(authSchemes, loginEndpoints, acquired) {
  console.log('\n─── Auth Summary ─────────────────────────────────────────────');

  if (acquired.length > 0) {
    console.log('\n Tokens acquired automatically:');
    for (const a of acquired) {
      console.log(`  ✓ ${a.tag}: ${a.tokenVar} = ${a.token.substring(0, 20)}...`);
      if (a.userId) console.log(`    User ID: ${a.userId}`);
    }
  }

  if (loginEndpoints.length === 0) {
    console.log('\n No login endpoints found in swagger.');
    console.log(' Manual steps required:');
    console.log('   1. Obtain your API token through your normal login flow');
    console.log('   2. Add it to the environment file:');
    console.log(`      ${ENV_PATH}`);
    for (const scheme of authSchemes) {
      if (scheme.type === 'customHeader') {
        for (const h of scheme.headers) {
          const varName = h.toLowerCase().replace(/-/g, '_');
          console.log(`   Set variable: ${varName} = <your token>`);
        }
      }
    }
  }

  if (acquired.length === 0 && loginEndpoints.length > 0) {
    console.log('\n Login endpoints found but token acquisition failed.');
    console.log(' Likely cause: credentials not provided or wrong field names.');
    console.log('\n Create a credentials.json file:');
    console.log(JSON.stringify({
      username: 'your_username',
      password: 'your_password',
      email:    'your_email@example.com'
    }, null, 2));
    console.log(`\n Then run:`);
    console.log(`   node auth-resolver.js --swagger ${SWAGGER_PATH} --env ${ENV_PATH} --credentials ./credentials.json`);
  }

  console.log('\n For BOLA/IDOR tests you need TWO accounts (attacker + victim).');
  console.log(' Add both to credentials.json:');
  console.log(JSON.stringify({
    attacker: { username: 'attacker_user', password: 'AttackerPass123!' },
    victim:   { username: 'victim_user',   password: 'VictimPass123!' }
  }, null, 2));
  console.log('──────────────────────────────────────────────────────────────\n');
}

// ─── Main ─────────────────────────────────────────────────────────────────────

(async () => {
  console.log('\n── Auth Resolver ─────────────────────────────────────────────');
  console.log(`Swagger:     ${SWAGGER_PATH}`);
  console.log(`Environment: ${ENV_PATH}`);
  console.log(`Credentials: ${fs.existsSync(CREDS_PATH) ? CREDS_PATH : 'NOT FOUND — using env vars'}`);
  console.log(`Base URL:    ${BASE_URL}\n`);

  // Detect auth scheme
  const authSchemes = detectAuthScheme(swagger);
  console.log(`Auth schemes detected: ${authSchemes.length > 0
    ? authSchemes.map(s => s.type).join(', ')
    : 'none (all endpoints may be public)'}`);

  // Find login endpoints
  const loginEndpoints = findLoginEndpoints(swagger);
  console.log(`Login endpoints found: ${loginEndpoints.length}`);
  loginEndpoints.forEach(e => console.log(`  ${e.method} ${e.path} — ${e.summary}`));

  const acquired = [];
  const envUpdates = {};

  // Try to acquire tokens for each unique tag that has a login endpoint
  for (const loginEp of loginEndpoints) {
    const tag = loginEp.tags[0] || 'default';

    // Use attacker credentials if available, fall back to generic
    const creds = credentials.attacker || credentials;

    console.log(`\nAcquiring token for tag: ${tag}`);
    const result = await acquireToken(loginEp, creds);

    if (result.success) {
      console.log(`  Token acquired (found in: ${result.tokenField})`);

      // Map token to the variable names the collection expects
      // Convention: api{N}_auth or api{N}_token based on tag name
      const tagLower = tag.toLowerCase().replace(/[^a-z0-9]/g, '');
      const tokenVar = `${tagLower}_token`;
      const authVar  = `${tagLower}_auth`;

      envUpdates[tokenVar] = result.token;
      envUpdates[authVar]  = result.token;

      if (result.userId) {
        envUpdates[`${tagLower}_user_id`] = String(result.userId);
        envUpdates[`${tagLower}_attacker_token`] = result.token;
        envUpdates[`${tagLower}_attacker_id`]    = String(result.userId);
      }

      acquired.push({ tag, tokenVar, token: result.token, userId: result.userId });

      // If we have victim credentials, acquire a victim token too
      if (credentials.victim) {
        console.log(`  Acquiring victim token for BOLA tests...`);
        const victimResult = await acquireToken(loginEp, credentials.victim);
        if (victimResult.success) {
          envUpdates[`${tagLower}_victim_token`] = victimResult.token;
          envUpdates[`${tagLower}_victim_id`]    = String(victimResult.userId || '');
          console.log(`  Victim token acquired`);
        }
      }
    } else {
      console.log(`  Failed: ${result.error || 'HTTP ' + result.status}`);
    }
  }

  // Write all acquired tokens to environment
  if (Object.keys(envUpdates).length > 0) {
    updateEnvironment(ENV_PATH, envUpdates);
    console.log(`\n  ${Object.keys(envUpdates).length} variables written to environment`);
  }

  printManualInstructions(authSchemes, loginEndpoints, acquired);

  // Exit 0 if we got at least something, exit 2 if nothing acquired (not a hard failure)
  process.exit(acquired.length > 0 ? 0 : 2);
})();
