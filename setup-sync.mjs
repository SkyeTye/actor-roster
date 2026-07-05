#!/usr/bin/env node
// Encrypts a gist-scoped GitHub token into TOKEN_VAULT inside index.html,
// and uploads seed.json (freshly encrypted) to the sync gist.
// Usage: node setup-sync.mjs "<passphrase>" "<gist token>"
// Run this after encrypt-roster.mjs whenever the password changes.

import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";

const [passphrase, token] = process.argv.slice(2);
if (!passphrase || !token) {
  console.error('Usage: node setup-sync.mjs "<passphrase>" "<gist token>"');
  process.exit(1);
}

let html = readFileSync("index.html", "utf8");
const vault = JSON.parse(html.match(/const VAULT = (\{.*?\}); \/\/ @vault/)[1]);
const gistId = html.match(/const GIST_ID = "([^"]*)"; \/\/ @gist-id/)[1];
if (!gistId) throw new Error("GIST_ID is empty in index.html");

const b64 = buf => Buffer.from(buf).toString("base64");
const b64d = s => new Uint8Array(Buffer.from(s, "base64"));

const baseKey = await crypto.subtle.importKey(
  "raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey(
  { name: "PBKDF2", salt: b64d(vault.salt), iterations: vault.iterations, hash: "SHA-256" },
  baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

async function encryptBlob(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(obj))));
  return { iv: b64(iv), data: b64(data) };
}

// 1. Token vault into index.html
const tokenVault = JSON.stringify(await encryptBlob(token.trim()));
html = html.replace(/const TOKEN_VAULT = .*; \/\/ @token-vault/,
  `const TOKEN_VAULT = ${tokenVault}; // @token-vault`);
writeFileSync("index.html", html);
console.log("Token encrypted into index.html.");

// 2. Push freshly encrypted seed.json to the gist
const roster = JSON.parse(readFileSync("seed.json", "utf8"));
const blob = await encryptBlob(roster);
blob.salt = vault.salt;
blob.iterations = vault.iterations;

const res = await fetch(`https://api.github.com/gists/${gistId}`, {
  method: "PATCH",
  headers: {
    Authorization: `Bearer ${token.trim()}`,
    Accept: "application/vnd.github+json",
    "Content-Type": "application/json"
  },
  body: JSON.stringify({ files: { "roster.vault.json": { content: JSON.stringify(blob) } } })
});
if (!res.ok) throw new Error(`Gist update failed: ${res.status} ${await res.text()}`);
console.log(`Gist ${gistId} updated with ${roster.length} actors (encrypted).`);
