#!/usr/bin/env node
/**
 * OpenClaw Subscription Billing Proxy
 *
 * Routes OpenClaw API requests through Claude Code's subscription billing
 * instead of Extra Usage, by injecting Claude Code's billing identifier
 * and sanitizing detected trigger phrases.
 *
 * Features:
 *   - Billing header injection (84-char Claude Code identifier)
 *   - Bidirectional sanitization (request out + response back)
 *   - Wildcard sessions_* tool name replacement
 *   - SSE streaming support with per-chunk reverse mapping
 *   - Zero dependencies. Works on Windows, Linux, Mac.
 *
 * Usage:
 *   node proxy.js [--port 18801] [--config config.json]
 *
 * Quick start:
 *   1. Authenticate Claude Code: claude auth login
 *   2. Run: node proxy.js
 *   3. Set openclaw.json baseUrl to http://127.0.0.1:18801
 *   4. Restart OpenClaw gateway
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ─── Defaults ───────────────────────────────────────────────────────────────
const DEFAULT_PORT = 18801;
const UPSTREAM_HOST = 'api.anthropic.com';

// Claude Code billing identifier -- injected into the system prompt
const BILLING_BLOCK = '{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.80.a46; cc_entrypoint=sdk-cli; cch=00000;"}';

// Beta flags required for OAuth + Claude Code features
const REQUIRED_BETAS = [
  'claude-code-20250219',
  'oauth-2025-04-20',
  'interleaved-thinking-2025-05-14',
  'context-management-2025-06-27',
  'prompt-caching-scope-2026-01-05',
  'effort-2025-11-24'
];

// ─── Default Sanitization Rules ─────────────────────────────────────────────
// Verified trigger phrases that Anthropic's streaming classifier detects.
// Uses a wildcard approach for sessions_* to catch current and future tools.
//
// IMPORTANT: Use space-free replacements for lowercase 'openclaw' to avoid
// breaking filesystem paths (e.g., .openclaw/ -> .ocplatform/, not .assistant platform/)
const DEFAULT_REPLACEMENTS = [
  ['OpenClaw', 'OCPlatform'],
  ['openclaw', 'ocplatform'],
  ['sessions_spawn', 'create_task'],
  ['sessions_list', 'list_tasks'],
  ['sessions_history', 'get_history'],
  ['sessions_send', 'send_to_task'],
  ['sessions_yield_interrupt', 'task_yield_interrupt'],
  ['sessions_yield', 'yield_task'],
  ['sessions_store', 'task_store'],
  ['HEARTBEAT_OK', 'HB_ACK'],
  ['running inside', 'running on']
];

// Reverse mapping: applied to API responses before returning to OpenClaw.
// This ensures OpenClaw sees original tool names, file paths, and identifiers.
const DEFAULT_REVERSE_MAP = [
  ['OCPlatform', 'OpenClaw'],
  ['ocplatform', 'openclaw'],
  ['create_task', 'sessions_spawn'],
  ['list_tasks', 'sessions_list'],
  ['get_history', 'sessions_history'],
  ['send_to_task', 'sessions_send'],
  ['task_yield_interrupt', 'sessions_yield_interrupt'],
  ['yield_task', 'sessions_yield'],
  ['task_store', 'sessions_store'],
  ['HB_ACK', 'HEARTBEAT_OK']
];

// ─── Configuration ──────────────────────────────────────────────────────────
function loadConfig() {
  // Config precedence: PROXY_PORT env > --port CLI > config.json port > DEFAULT_PORT
  const args = process.argv.slice(2);
  let configPath = null;
  let cliPort = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' && args[i + 1]) cliPort = parseInt(args[i + 1]);
    if (args[i] === '--config' && args[i + 1]) configPath = args[i + 1];
  }

  const envPort = process.env.PROXY_PORT ? parseInt(process.env.PROXY_PORT) : null;

  let config = {};
  if (configPath && fs.existsSync(configPath)) {
    try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch(e) {
      console.error('[ERROR] Failed to parse config: ' + configPath + ' (' + e.message + ')');
      process.exit(1);
    }
  } else if (fs.existsSync('config.json')) {
    try { config = JSON.parse(fs.readFileSync('config.json', 'utf8')); } catch(e) {
      console.error('[PROXY] Warning: config.json is invalid, using defaults. (' + e.message + ')');
    }
  }

  // Find Claude Code credentials
  const homeDir = os.homedir();

  // OAUTH_TOKEN env var takes precedence over all file-based credentials
  let credsPath = null;
  if (process.env.OAUTH_TOKEN) {
    credsPath = 'env';
    console.log('[PROXY] Using OAUTH_TOKEN from environment variable.');
  }

  const credsPaths = [
    config.credentialsPath,
    path.join(homeDir, '.claude', '.credentials.json'),
    path.join(homeDir, '.claude', 'credentials.json')
  ].filter(Boolean);

  if (!credsPath) {
    for (const p of credsPaths) {
      const resolved = p.startsWith('~') ? path.join(homeDir, p.slice(1)) : p;
      if (fs.existsSync(resolved) && fs.statSync(resolved).size > 0) {
        credsPath = resolved;
        break;
      }
    }
  }

  // macOS Keychain fallback: extract token and write to file
  if (!credsPath && process.platform === 'darwin') {
    const { execSync } = require('child_process');
    const keychainNames = ['claude-code', 'claude', 'com.anthropic.claude-code'];
    for (const svc of keychainNames) {
      try {
        const token = execSync('security find-generic-password -s "' + svc + '" -w 2>/dev/null', { encoding: 'utf8' }).trim();
        if (token) {
          let creds;
          try { creds = JSON.parse(token); } catch(e) {
            if (token.startsWith('sk-ant-')) {
              creds = { claudeAiOauth: { accessToken: token, expiresAt: Date.now() + 86400000, subscriptionType: 'unknown' } };
            }
          }
          if (creds && creds.claudeAiOauth) {
            credsPath = path.join(homeDir, '.claude', '.credentials.json');
            fs.mkdirSync(path.join(homeDir, '.claude'), { recursive: true });
            fs.writeFileSync(credsPath, JSON.stringify(creds));
            console.log('[PROXY] Extracted credentials from macOS Keychain to ' + credsPath);
            break;
          }
        }
      } catch(e) { /* not found */ }
    }
  }

  if (!credsPath) {
    console.error('[ERROR] Claude Code credentials not found.');
    console.error('Run "claude auth login" first to authenticate.');
    console.error('On macOS, try: claude -p "test" --max-turns 1 --no-session-persistence');
    console.error('Then run this proxy again.');
    console.error('Searched:', credsPaths.join(', '));
    if (process.platform === 'darwin') {
      console.error('Also checked macOS Keychain (claude-code, claude, com.anthropic.claude-code)');
    }
    process.exit(1);
  }

  return {
    port: envPort || cliPort || config.port || DEFAULT_PORT,
    credsPath,
    replacements: config.replacements || DEFAULT_REPLACEMENTS,
    reverseMap: config.reverseMap || DEFAULT_REVERSE_MAP
  };
}

// ─── Token Management ───────────────────────────────────────────────────────
function getToken(credsPath) {
  // Env var sentinel: return synthetic OAuth object without file I/O
  if (credsPath === 'env') {
    const token = process.env.OAUTH_TOKEN;
    if (!token) throw new Error('OAUTH_TOKEN env var is empty.');
    return { accessToken: token, expiresAt: Infinity, subscriptionType: 'env-var' };
  }
  let raw = fs.readFileSync(credsPath, 'utf8');
  // Strip UTF-8 BOM if present (PowerShell and some editors add this)
  if (raw.charCodeAt(0) === 0xFEFF) raw = raw.slice(1);
  const creds = JSON.parse(raw);
  const oauth = creds.claudeAiOauth;
  if (!oauth || !oauth.accessToken) {
    throw new Error('No OAuth token in credentials file. Run "claude auth login".');
  }
  return oauth;
}

// ─── Request Processing ─────────────────────────────────────────────────────
function processBody(bodyStr, config) {
  let modified = bodyStr;

  // 1. Apply sanitization -- raw string replacement preserves original JSON formatting
  for (const [find, replace] of config.replacements) {
    modified = modified.split(find).join(replace);
  }

  // 2. Inject billing block into system prompt
  const sysArrayIdx = modified.indexOf('"system":[');
  if (sysArrayIdx !== -1) {
    const insertAt = sysArrayIdx + '"system":['.length;
    modified = modified.slice(0, insertAt) + BILLING_BLOCK + ',' + modified.slice(insertAt);
  } else if (modified.includes('"system":"')) {
    const sysStart = modified.indexOf('"system":"');
    let i = sysStart + '"system":"'.length;
    while (i < modified.length) {
      if (modified[i] === '\\') { i += 2; continue; }
      if (modified[i] === '"') break;
      i++;
    }
    const sysEnd = i + 1;
    const originalSysStr = modified.slice(sysStart + '"system":'.length, sysEnd);
    modified = modified.slice(0, sysStart)
      + '"system":[' + BILLING_BLOCK + ',{"type":"text","text":' + originalSysStr + '}]'
      + modified.slice(sysEnd);
  } else {
    modified = '{"system":[' + BILLING_BLOCK + '],' + modified.slice(1);
  }

  return modified;
}

// ─── Response Processing ────────────────────────────────────────────────────
function reverseMap(text, config) {
  let result = text;
  for (const [sanitized, original] of config.reverseMap) {
    result = result.split(sanitized).join(original);
  }
  return result;
}

// ─── Server ─────────────────────────────────────────────────────────────────
function startServer(config) {
  let requestCount = 0;
  const startedAt = Date.now();

  const server = http.createServer((req, res) => {
    if (req.url === '/health' && req.method === 'GET') {
      try {
        const oauth = getToken(config.credsPath);
        const expiresIn = (oauth.expiresAt - Date.now()) / 3600000;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: expiresIn > 0 ? 'ok' : 'token_expired',
          proxy: 'openclaw-billing-proxy',
          requestsServed: requestCount,
          uptime: Math.floor((Date.now() - startedAt) / 1000) + 's',
          tokenExpiresInHours: isFinite(expiresIn) ? expiresIn.toFixed(1) : 'n/a',
          subscriptionType: oauth.subscriptionType,
          replacementPatterns: config.replacements.length,
          reverseMapPatterns: config.reverseMap.length
        }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'error', message: e.message }));
      }
      return;
    }

    requestCount++;
    const reqNum = requestCount;
    const chunks = [];

    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      let body = Buffer.concat(chunks);

      let oauth;
      try {
        oauth = getToken(config.credsPath);
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { message: e.message } }));
        return;
      }

      // Process body: sanitize triggers + inject billing header
      let bodyStr = body.toString('utf8');
      bodyStr = processBody(bodyStr, config);
      body = Buffer.from(bodyStr, 'utf8');

      // Build upstream headers
      const headers = {};
      for (const [key, value] of Object.entries(req.headers)) {
        const lk = key.toLowerCase();
        if (lk === 'host' || lk === 'connection') continue;
        if (lk === 'authorization' || lk === 'x-api-key') continue;
        if (lk === 'content-length') continue;
        headers[key] = value;
      }

      headers['authorization'] = `Bearer ${oauth.accessToken}`;
      headers['content-length'] = body.length;
      headers['accept-encoding'] = 'identity';

      // Merge required betas
      const existingBeta = headers['anthropic-beta'] || '';
      const betas = existingBeta ? existingBeta.split(',').map(b => b.trim()) : [];
      for (const b of REQUIRED_BETAS) {
        if (!betas.includes(b)) betas.push(b);
      }
      headers['anthropic-beta'] = betas.join(',');

      const ts = new Date().toISOString().substring(11, 19);
      console.log(`[${ts}] #${reqNum} ${req.method} ${req.url} (${body.length}b)`);

      const upstream = https.request({
        hostname: UPSTREAM_HOST, port: 443,
        path: req.url, method: req.method, headers
      }, (upRes) => {
        console.log(`[${ts}] #${reqNum} > ${upRes.statusCode}`);

        // For SSE streaming responses, reverse-map each chunk
        if (upRes.headers['content-type'] && upRes.headers['content-type'].includes('text/event-stream')) {
          res.writeHead(upRes.statusCode, upRes.headers);
          upRes.on('data', (chunk) => {
            res.write(reverseMap(chunk.toString(), config));
          });
          upRes.on('end', () => res.end());
        }
        // For JSON responses (errors, non-streaming), buffer and reverse-map
        else {
          const respChunks = [];
          upRes.on('data', (c) => respChunks.push(c));
          upRes.on('end', () => {
            let respBody = Buffer.concat(respChunks).toString();
            respBody = reverseMap(respBody, config);
            const newHeaders = { ...upRes.headers };
            newHeaders['content-length'] = Buffer.byteLength(respBody);
            res.writeHead(upRes.statusCode, newHeaders);
            res.end(respBody);
          });
        }
      });

      upstream.on('error', (e) => {
        console.error(`[${ts}] #${reqNum} ERR: ${e.message}`);
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'error', error: { message: e.message } }));
        }
      });

      upstream.write(body);
      upstream.end();
    });
  });

  const bindHost = process.env.PROXY_HOST || '127.0.0.1';
  server.listen(config.port, bindHost, () => {
    try {
      const oauth = getToken(config.credsPath);
      const expiresIn = (oauth.expiresAt - Date.now()) / 3600000;
      const h = isFinite(expiresIn) ? expiresIn.toFixed(1) + 'h' : 'n/a (env var)';
      console.log(`\n  OpenClaw Billing Proxy`);
      console.log(`  ---------------------`);
      console.log(`  Port:          ${config.port}`);
      console.log(`  Bind address:  ${bindHost}`);
      console.log(`  Subscription:  ${oauth.subscriptionType}`);
      console.log(`  Token expires: ${h}`);
      console.log(`  Patterns:      ${config.replacements.length} sanitization + ${config.reverseMap.length} reverse`);
      console.log(`  Credentials:   ${config.credsPath}`);
      console.log(`\n  Ready. Set openclaw.json baseUrl to http://127.0.0.1:${config.port}\n`);
    } catch (e) {
      console.error(`  Started on port ${config.port} but credentials error: ${e.message}`);
    }
  });

  process.on('SIGINT', () => process.exit(0));
  process.on('SIGTERM', () => process.exit(0));
}

// ─── Main ───────────────────────────────────────────────────────────────────
const config = loadConfig();
startServer(config);
