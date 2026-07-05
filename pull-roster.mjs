#!/usr/bin/env node
// Downloads the latest roster from the sync gist, decrypts it, and writes
// it to seed.json — use for backups or before changing the password.
// Usage: node pull-roster.mjs "<passphrase>"

import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";

const passphrase = process.argv[2];
if (!passphrase) {
  console.error('Usage: node pull-roster.mjs "<passphrase>"');
  process.exit(1);
}

const html = readFileSync("index.html", "utf8");
const vault = JSON.parse(html.match(/const VAULT = (\{.*?\}); \/\/ @vault/)[1]);
const gistId = html.match(/const GIST_ID = "([^"]*)"; \/\/ @gist-id/)[1];
const tokenVault = JSON.parse(html.match(/const TOKEN_VAULT = (\{.*?\}); \/\/ @token-vault/)[1]);

const b64d = s => new Uint8Array(Buffer.from(s, "base64"));

const baseKey = await crypto.subtle.importKey(
  "raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey(
  { name: "PBKDF2", salt: b64d(vault.salt), iterations: vault.iterations, hash: "SHA-256" },
  baseKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);

async function decryptBlob(blob) {
  const buf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64d(blob.iv) }, key, b64d(blob.data));
  return JSON.parse(new TextDecoder().decode(buf));
}

const token = await decryptBlob(tokenVault);
const res = await fetch(`https://api.github.com/gists/${gistId}`, {
  headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" }
});
if (!res.ok) throw new Error(`Gist fetch failed: ${res.status}`);
const gist = await res.json();
const roster = await decryptBlob(JSON.parse(gist.files["roster.vault.json"].content));

writeFileSync("seed.json", JSON.stringify(roster, null, 2) + "\n");
console.log(`Pulled ${roster.length} actors from the gist into seed.json.`);
