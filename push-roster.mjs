#!/usr/bin/env node
// Encrypts seed.json and uploads it to the sync gist, making it the live
// roster on all devices. Counterpart of pull-roster.mjs.
// Usage: node push-roster.mjs "<passphrase>"

import { readFileSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";

const passphrase = process.argv[2];
if (!passphrase) {
  console.error('Usage: node push-roster.mjs "<passphrase>"');
  process.exit(1);
}

const html = readFileSync("index.html", "utf8");
const vault = JSON.parse(html.match(/const VAULT = (\{.*?\}); \/\/ @vault/)[1]);
const gistId = html.match(/const GIST_ID = "([^"]*)"; \/\/ @gist-id/)[1];
const tokenVault = JSON.parse(html.match(/const TOKEN_VAULT = (\{.*?\}); \/\/ @token-vault/)[1]);

const b64 = buf => Buffer.from(buf).toString("base64");
const b64d = s => new Uint8Array(Buffer.from(s, "base64"));

const baseKey = await crypto.subtle.importKey(
  "raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey(
  { name: "PBKDF2", salt: b64d(vault.salt), iterations: vault.iterations, hash: "SHA-256" },
  baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

async function decryptBlob(blob) {
  const buf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64d(blob.iv) }, key, b64d(blob.data));
  return JSON.parse(new TextDecoder().decode(buf));
}

const roster = JSON.parse(readFileSync("seed.json", "utf8"));
const iv = crypto.getRandomValues(new Uint8Array(12));
const data = new Uint8Array(await crypto.subtle.encrypt(
  { name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(roster))));
const blob = { iv: b64(iv), data: b64(data), salt: vault.salt, iterations: vault.iterations };

const token = await decryptBlob(tokenVault);
const res = await fetch(`https://api.github.com/gists/${gistId}`, {
  method: "PATCH",
  headers: {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "Content-Type": "application/json"
  },
  body: JSON.stringify({ files: { "roster.vault.json": { content: JSON.stringify(blob) } } })
});
if (!res.ok) throw new Error(`Gist update failed: ${res.status} ${await res.text()}`);
console.log(`Pushed ${roster.length} actors to the gist.`);
