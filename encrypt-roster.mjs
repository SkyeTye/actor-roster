#!/usr/bin/env node
// Encrypts seed.json into the VAULT constant inside index.html.
// Usage: node encrypt-roster.mjs "<passphrase>"
// seed.json stays local (gitignored); only the ciphertext is written into index.html.

import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";

const passphrase = process.argv[2];
if (!passphrase) {
  console.error('Usage: node encrypt-roster.mjs "<passphrase>"');
  process.exit(1);
}

const PBKDF2_ITERATIONS = 310000;
const seed = JSON.stringify(JSON.parse(readFileSync("seed.json", "utf8")));

const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));

const baseKey = await crypto.subtle.importKey(
  "raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey(
  { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
  baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
  { name: "AES-GCM", iv }, key, new TextEncoder().encode(seed)));

// Round-trip check
const plain = new TextDecoder().decode(
  await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext));
if (plain !== seed) throw new Error("Round-trip verification failed");

const b64 = buf => Buffer.from(buf).toString("base64");
const vault = JSON.stringify({
  salt: b64(salt), iv: b64(iv), data: b64(ciphertext), iterations: PBKDF2_ITERATIONS
});

const html = readFileSync("index.html", "utf8");
const marker = /const VAULT = .*; \/\/ @vault/;
if (!marker.test(html)) throw new Error("@vault marker not found in index.html");
writeFileSync("index.html", html.replace(marker, `const VAULT = ${vault}; // @vault`));

console.log(`Encrypted ${seed.length} bytes of roster data into index.html (round-trip verified).`);
