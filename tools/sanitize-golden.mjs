#!/usr/bin/env node
// Sanitize a recorded upstream response before it becomes a fixture/golden.
//
//   node tools/sanitize-golden.mjs raw.json > golden/scores.json
//   node tools/sanitize-golden.mjs raw.json out.json
//
// The authoritative check is the Rust gate
// `re0auth-archtest` -> `fixtures_and_golden_carry_no_live_secrets`; this tool is
// a convenience that should be kept in sync with it. If this tool misses a
// secret, the gate still fails the commit — the gate wins.
//
// Rule (ADR-0035): field names stay, sensitive values become "<redacted>".

import { readFileSync, writeFileSync } from 'node:fs';

const PLACEHOLDER = '<redacted>';

// Same set as the Rust gate's `SENSITIVE_KEYS` (case-insensitive).
const SENSITIVE_KEYS = new Set([
	'stoken',
	'session_token',
	'session_cookie',
	'sessioncookie',
	'sessiontoken',
	'game_password',
	'tap_password',
	'taptap_password',
	'password',
	'secret',
	'client_secret',
	'token',
	'access_token',
	'refresh_token',
	'api_token',
	'authorization',
	'cookie'
]);

function looksLikeJwt(token) {
	const parts = token.split('.');
	if (parts.length !== 3) return false;
	const [header, payload, signature] = parts;
	return (
		token.length >= 40 &&
		header.startsWith('eyJ') &&
		header.length >= 10 &&
		payload.length >= 10 &&
		signature.length >= 10
	);
}

function looksLikeLeancloud(token) {
	return token.startsWith('r:') && token.length >= 12 && /^[A-Za-z0-9._-]+$/.test(token.slice(2));
}

function looksLikeHex(token) {
	return token.length >= 32 && /^[0-9a-fA-F]+$/.test(token);
}

function looksLikeSecret(value) {
	return looksLikeJwt(value) || looksLikeLeancloud(value) || looksLikeHex(value);
}

function redact(value) {
	if (Array.isArray(value)) return value.map(redact);
	if (value && typeof value === 'object') {
		const out = {};
		for (const [key, child] of Object.entries(value)) {
			out[key] = SENSITIVE_KEYS.has(key.toLowerCase()) ? PLACEHOLDER : redact(child);
		}
		return out;
	}
	if (typeof value === 'string' && looksLikeSecret(value)) return PLACEHOLDER;
	return value;
}

const [, , input, output] = process.argv;
if (!input) {
	process.stderr.write('usage: sanitize-golden.mjs <input> [output]\n');
	process.exit(2);
}

const raw = readFileSync(input, 'utf8');
let sanitized;
try {
	sanitized = JSON.stringify(redact(JSON.parse(raw)), null, 2) + '\n';
} catch {
	// Not JSON: redact secret-shaped runs in place and keep the surrounding text.
	sanitized = raw.replace(/[A-Za-z0-9._:-]{12,}/g, (token) =>
		looksLikeSecret(token) ? PLACEHOLDER : token
	);
}

if (output) writeFileSync(output, sanitized);
else process.stdout.write(sanitized);
