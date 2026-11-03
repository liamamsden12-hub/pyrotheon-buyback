#!/usr/bin/env node
/* =====================================================================
   Pyrotheon members area: account and content manager.

   The site is static and the repo is public, so nothing secret is ever
   committed in plain text. members/vault.json holds:
     - users:   one entry per account, keyed by a hash of the username.
                Each entry wraps the vault's master key with a key derived
                from that account's password (PBKDF2-SHA256, 600k rounds).
     - roster:  the list of usernames and display names, encrypted.
     - content: the members page (HTML), encrypted with the master key.
   The browser login does the same derivation to unlock the content.

   Commands (run from the repo root):
     node tools/members.mjs init <username> "<Display Name>"
     node tools/members.mjs add <username> "<Display Name>" [--generate]
     node tools/members.mjs remove <username>
     node tools/members.mjs passwd <username> [--generate]
     node tools/members.mjs list
     node tools/members.mjs open      decrypt content to members/_plain/content.html
     node tools/members.mjs seal      encrypt members/_plain/content.html into the vault
     node tools/members.mjs rotate    new master key, new passwords for everyone

   Every command except init needs an existing login to unlock the vault.
   It is asked for, or read from PYRO_USER / PYRO_PASS. A new account's
   password is asked for, read from PYRO_NEW_PASS, or made up with --generate.
   ===================================================================== */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import { randomBytes, randomInt } from "node:crypto";

const subtle = globalThis.crypto.subtle;
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const VAULT = join(ROOT, "members", "vault.json");
const PLAIN_DIR = join(ROOT, "members", "_plain");
const PLAIN = join(PLAIN_DIR, "content.html");
const STARTER = join(ROOT, "tools", "starter-content.html");
const ITERATIONS = 600000;
const MIN_PASSWORD = 12;
const enc = new TextEncoder(), dec = new TextDecoder();

const b64 = buf => Buffer.from(buf).toString("base64");
const unb64 = s => new Uint8Array(Buffer.from(s, "base64"));
const normUser = u => String(u || "").trim().toLowerCase();

async function userId(username) {
  const h = await subtle.digest("SHA-256", enc.encode("pyrotheon-members:" + normUser(username)));
  return Buffer.from(h).toString("hex");
}
async function deriveKek(password, salt, iterations) {
  const base = await subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, base,
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
const importMaster = raw => subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
async function seal(key, text, aad) {
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(aad) }, key, enc.encode(text));
  return { iv: b64(iv), ct: b64(ct) };
}
async function unseal(key, box, aad) {
  const pt = await subtle.decrypt({ name: "AES-GCM", iv: unb64(box.iv), additionalData: enc.encode(aad) }, key, unb64(box.ct));
  return dec.decode(pt);
}

async function makeUserEntry(masterRaw, username, name, password) {
  const salt = randomBytes(16);
  const kek = await deriveKek(password, salt, ITERATIONS);
  const box = await seal(kek, JSON.stringify({ mk: b64(masterRaw), name, u: normUser(username) }), "user");
  return { salt: b64(salt), iterations: ITERATIONS, ...box };
}

function loadVault() {
  if (!existsSync(VAULT)) fail("No vault yet. Run: node tools/members.mjs init <username> \"<Display Name>\"");
  return JSON.parse(readFileSync(VAULT, "utf8"));
}
function saveVault(v) {
  mkdirSync(dirname(VAULT), { recursive: true });
  writeFileSync(VAULT, JSON.stringify(v, null, 2) + "\n");
}

/* ---------- prompts ---------- */
function ask(question, hidden = false) {
  return new Promise(resolve => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (hidden) {
      rl._writeToOutput = s => { if (s.includes(question)) rl.output.write(s); else if (s === "\r\n" || s === "\n") rl.output.write(s); };
    }
    rl.question(question, a => { rl.close(); if (hidden) process.stdout.write("\n"); resolve(a); });
  });
}
function fail(msg) { console.error("✖ " + msg); process.exit(1); }

function generatePassword() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const group = () => Array.from({ length: 5 }, () => alphabet[randomInt(alphabet.length)]).join("");
  return [group(), group(), group(), group()].join("-");
}
async function newPassword(args, label) {
  if (args.includes("--generate")) return { pw: generatePassword(), generated: true };
  let pw = process.env.PYRO_NEW_PASS;
  if (!pw) {
    pw = await ask(`Password for ${label}: `, true);
    const again = await ask("Type it again: ", true);
    if (pw !== again) fail("Passwords did not match.");
  }
  if (pw.length < MIN_PASSWORD) fail(`Use at least ${MIN_PASSWORD} characters. Anyone can download the vault and guess offline, so length matters.`);
  return { pw, generated: false };
}

/* Unlock the vault with an existing login. Returns master key bytes + roster. */
async function unlock(v) {
  const user = process.env.PYRO_USER || await ask("Your username: ");
  const pass = process.env.PYRO_PASS || await ask("Your password: ", true);
  const entry = v.users[await userId(user)];
  if (!entry) fail("Login failed.");
  let payload;
  try {
    const kek = await deriveKek(pass, unb64(entry.salt), entry.iterations);
    payload = JSON.parse(await unseal(kek, entry, "user"));
  } catch { fail("Login failed."); }
  const masterRaw = unb64(payload.mk);
  const master = await importMaster(masterRaw);
  const roster = JSON.parse(await unseal(master, v.roster, "roster"));
  return { masterRaw, master, roster, me: payload.u };
}
async function writeRoster(v, master, roster) { v.roster = await seal(master, JSON.stringify(roster), "roster"); }

/* ---------- commands ---------- */
const [cmd, ...rest] = process.argv.slice(2);
const pos = rest.filter(a => !a.startsWith("--"));

async function main() {
  switch (cmd) {
    case "init": {
      if (existsSync(VAULT)) fail("A vault already exists. Use add / passwd / rotate instead.");
      const [username, name] = pos; if (!username || !name) fail('Usage: init <username> "<Display Name>"');
      const masterRaw = randomBytes(32); const master = await importMaster(masterRaw);
      const { pw, generated } = await newPassword(rest, username);
      const v = { v: 1, kdf: { name: "PBKDF2", hash: "SHA-256", iterations: ITERATIONS }, users: {}, roster: null, content: null };
      v.users[await userId(username)] = await makeUserEntry(masterRaw, username, name, pw);
      await writeRoster(v, master, { [normUser(username)]: { name, added: new Date().toISOString().slice(0, 10) } });
      const html = readFileSync(STARTER, "utf8");
      v.content = { ...(await seal(master, html, "content")), updated: new Date().toISOString() };
      saveVault(v);
      console.log(`✔ Vault created with account "${normUser(username)}".` + (generated ? `\n  Password: ${pw}` : ""));
      break;
    }
    case "add": {
      const [username, name] = pos; if (!username || !name) fail('Usage: add <username> "<Display Name>"');
      const v = loadVault(); const { masterRaw, master, roster } = await unlock(v);
      const id = await userId(username);
      if (v.users[id]) fail(`"${normUser(username)}" already exists. Use passwd to change the password.`);
      const { pw, generated } = await newPassword(rest, username);
      v.users[id] = await makeUserEntry(masterRaw, username, name, pw);
      roster[normUser(username)] = { name, added: new Date().toISOString().slice(0, 10) };
      await writeRoster(v, master, roster); saveVault(v);
      console.log(`✔ Added "${normUser(username)}" (${name}).` + (generated ? `\n  Password: ${pw}` : ""));
      break;
    }
    case "passwd": {
      const [username] = pos; if (!username) fail("Usage: passwd <username>");
      const v = loadVault(); const { masterRaw, roster } = await unlock(v);
      const id = await userId(username); const r = roster[normUser(username)];
      if (!v.users[id] || !r) fail(`No account "${normUser(username)}".`);
      const { pw, generated } = await newPassword(rest, username);
      v.users[id] = await makeUserEntry(masterRaw, username, r.name, pw); saveVault(v);
      console.log(`✔ Password changed for "${normUser(username)}".` + (generated ? `\n  Password: ${pw}` : ""));
      break;
    }
    case "remove": {
      const [username] = pos; if (!username) fail("Usage: remove <username>");
      const v = loadVault(); const { master, roster } = await unlock(v);
      const id = await userId(username);
      if (!v.users[id]) fail(`No account "${normUser(username)}".`);
      if (Object.keys(v.users).length === 1) fail("That is the last account. Add another first.");
      delete v.users[id]; delete roster[normUser(username)];
      await writeRoster(v, master, roster); saveVault(v);
      console.log(`✔ Removed "${normUser(username)}". They can no longer sign in.\n  If they may have kept a copy of the unlocked key, run rotate as well.`);
      break;
    }
    case "list": {
      const v = loadVault(); const { roster } = await unlock(v);
      for (const [u, r] of Object.entries(roster)) console.log(`${u.padEnd(20)} ${r.name.padEnd(24)} added ${r.added}`);
      console.log(`Content last sealed ${v.content.updated}`);
      break;
    }
    case "open": {
      const v = loadVault(); const { master } = await unlock(v);
      mkdirSync(PLAIN_DIR, { recursive: true });
      writeFileSync(PLAIN, await unseal(master, v.content, "content"));
      console.log(`✔ Decrypted to members/_plain/content.html (git-ignored). Edit it, then run seal.`);
      break;
    }
    case "seal": {
      if (!existsSync(PLAIN)) fail("Nothing to seal. Run open first, or put your page at members/_plain/content.html.");
      const v = loadVault(); const { master } = await unlock(v);
      v.content = { ...(await seal(master, readFileSync(PLAIN, "utf8"), "content")), updated: new Date().toISOString() };
      saveVault(v);
      console.log("✔ Content encrypted into members/vault.json. Commit and push vault.json only.");
      break;
    }
    case "rotate": {
      const v = loadVault(); const { master, roster } = await unlock(v);
      const html = await unseal(master, v.content, "content");
      const newRaw = randomBytes(32); const newMaster = await importMaster(newRaw);
      v.users = {}; const issued = [];
      for (const [u, r] of Object.entries(roster)) {
        const pw = generatePassword();
        v.users[await userId(u)] = await makeUserEntry(newRaw, u, r.name, pw);
        issued.push([u, pw]);
      }
      await writeRoster(v, newMaster, roster);
      v.content = { ...(await seal(newMaster, html, "content")), updated: new Date().toISOString() };
      saveVault(v);
      console.log("✔ New master key. Every account has a new password:");
      for (const [u, pw] of issued) console.log(`  ${u.padEnd(20)} ${pw}`);
      break;
    }
    default:
      console.log(readFileSync(fileURLToPath(import.meta.url), "utf8").split("\n").slice(1, 29).join("\n").replace(/^ {0,3}/gm, ""));
  }
}
main();
