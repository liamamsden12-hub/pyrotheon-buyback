#!/usr/bin/env node
/* =====================================================================
   Pyrotheon members area: account and page manager.

   The site is static and the repo is public, so nothing secret is ever
   committed in plain text. members/vault.json holds:
     - users:  one entry per account, keyed by a hash of the username.
               Each wraps the vault's master key with a key derived from
               that account's password (PBKDF2-SHA256, 600k rounds).
     - roster: usernames and display names, encrypted.
     - nav:    the sidebar menu (page order, titles, icons), encrypted.
     - pages:  each members page (HTML), encrypted, under an opaque id.
   The browser login does the same derivation to unlock everything.

   Accounts:
     node tools/members.mjs init <username> "<Display Name>"
     node tools/members.mjs add <username> "<Display Name>" [--generate]
     node tools/members.mjs passwd <username> [--generate]
     node tools/members.mjs remove <username>
     node tools/members.mjs list
     node tools/members.mjs rotate      new master key, new passwords for all

   Pages (shown in the sidebar, in order):
     node tools/members.mjs pages
     node tools/members.mjs add-page <slug> "<Title>" [--icon=<icon>] [--after=<slug>]
     node tools/members.mjs rename-page <slug> "<Title>" [--icon=<icon>]
     node tools/members.mjs remove-page <slug>
     node tools/members.mjs open        decrypt menu + pages into members/_plain/
     node tools/members.mjs seal        encrypt members/_plain/ back into the vault
   Icons: home chart box truck flame doc users gear coins target

   Every command except init needs an existing login to unlock the vault:
   asked for, or read from PYRO_USER / PYRO_PASS. A new account's password
   is asked for, read from PYRO_NEW_PASS, or made up with --generate.
   ===================================================================== */
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import { randomBytes, randomInt } from "node:crypto";

const subtle = globalThis.crypto.subtle;
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const VAULT = join(ROOT, "members", "vault.json");
const PLAIN_DIR = join(ROOT, "members", "_plain");
const NAV_FILE = join(PLAIN_DIR, "nav.json");
const STARTER = join(ROOT, "tools", "starter-content.html");
const BLANK = join(ROOT, "tools", "blank-page.html");
const ITERATIONS = 600000;
const MIN_PASSWORD = 12;
const ICONS = ["home", "chart", "box", "truck", "flame", "doc", "users", "gear", "coins", "target"];
const enc = new TextEncoder(), dec = new TextDecoder();

const b64 = buf => Buffer.from(buf).toString("base64");
const unb64 = s => new Uint8Array(Buffer.from(s, "base64"));
const normUser = u => String(u || "").trim().toLowerCase();
const today = () => new Date().toISOString().slice(0, 10);
const newPageId = () => randomBytes(6).toString("hex");

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

/* ---------- pages ---------- */
const sealPage = async (master, id, html) => ({ ...(await seal(master, html, "page:" + id)), updated: new Date().toISOString() });
const unsealPage = (master, v, id) => unseal(master, v.pages[id], "page:" + id);
const readNav = async (master, v) => JSON.parse(await unseal(master, v.nav, "nav"));
const writeNav = async (master, v, nav) => { v.nav = await seal(master, JSON.stringify(nav), "nav"); };
function checkSlug(slug) {
  if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(slug || "")) fail("Slug must be lowercase letters, numbers and dashes, e.g. doctrine-supply.");
}
function checkIcon(icon) { if (icon && !ICONS.includes(icon)) fail("Icon must be one of: " + ICONS.join(", ")); }
function findPage(nav, slug) { const p = nav.find(n => n.slug === slug); if (!p) fail(`No page "${slug}". Run pages to see them.`); return p; }
const blankPage = title => readFileSync(BLANK, "utf8").split("{{title}}").join(title.replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])));

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
    if (hidden) rl._writeToOutput = s => { if (s.includes(question) || s === "\r\n" || s === "\n") rl.output.write(s); };
    rl.question(question, a => { rl.close(); if (hidden) process.stdout.write("\n"); resolve(a); });
  });
}
function fail(msg) { console.error("✖ " + msg); process.exit(1); }
function generatePassword() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const group = () => Array.from({ length: 5 }, () => alphabet[randomInt(alphabet.length)]).join("");
  return [group(), group(), group(), group()].join("-");
}
async function newPassword(label) {
  if (flags.generate) return { pw: generatePassword(), generated: true };
  let pw = process.env.PYRO_NEW_PASS;
  if (!pw) {
    pw = await ask(`Password for ${label}: `, true);
    if (pw !== await ask("Type it again: ", true)) fail("Passwords did not match.");
  }
  if (pw.length < MIN_PASSWORD) fail(`Use at least ${MIN_PASSWORD} characters. Anyone can download the vault and guess offline, so length matters.`);
  return { pw, generated: false };
}

/* Unlock with an existing login. Upgrades a v1 (single page) vault in place. */
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
  if (v.v === 1 && v.content) {
    const html = await unseal(master, v.content, "content");
    const id = newPageId();
    v.pages = { [id]: await sealPage(master, id, html) };
    await writeNav(master, v, [{ id, slug: "home", title: "Home", icon: "home" }]);
    delete v.content; v.v = 2;
    console.log("• Upgraded the vault to multi-page. Your existing page is now Home.");
  }
  return { masterRaw, master, roster, me: payload.u };
}
const writeRoster = async (v, master, roster) => { v.roster = await seal(master, JSON.stringify(roster), "roster"); };

/* ---------- commands ---------- */
const [cmd, ...rest] = process.argv.slice(2);
const pos = rest.filter(a => !a.startsWith("--"));
const flags = Object.fromEntries(rest.filter(a => a.startsWith("--")).map(a => { const [k, val] = a.slice(2).split("="); return [k, val ?? true]; }));

async function main() {
  switch (cmd) {
    case "init": {
      if (existsSync(VAULT)) fail("A vault already exists. Use add / passwd / rotate instead.");
      const [username, name] = pos; if (!username || !name) fail('Usage: init <username> "<Display Name>"');
      const masterRaw = randomBytes(32); const master = await importMaster(masterRaw);
      const { pw, generated } = await newPassword(username);
      const v = { v: 2, kdf: { name: "PBKDF2", hash: "SHA-256", iterations: ITERATIONS }, users: {}, roster: null, nav: null, pages: {} };
      v.users[await userId(username)] = await makeUserEntry(masterRaw, username, name, pw);
      await writeRoster(v, master, { [normUser(username)]: { name, added: today() } });
      const id = newPageId();
      v.pages[id] = await sealPage(master, id, readFileSync(STARTER, "utf8"));
      await writeNav(master, v, [{ id, slug: "home", title: "Home", icon: "home" }]);
      saveVault(v);
      console.log(`✔ Vault created with account "${normUser(username)}".` + (generated ? `\n  Password: ${pw}` : ""));
      break;
    }
    case "add": {
      const [username, name] = pos; if (!username || !name) fail('Usage: add <username> "<Display Name>"');
      const v = loadVault(); const { masterRaw, master, roster } = await unlock(v);
      const id = await userId(username);
      if (v.users[id]) fail(`"${normUser(username)}" already exists. Use passwd to change the password.`);
      const { pw, generated } = await newPassword(username);
      v.users[id] = await makeUserEntry(masterRaw, username, name, pw);
      roster[normUser(username)] = { name, added: today() };
      await writeRoster(v, master, roster); saveVault(v);
      console.log(`✔ Added "${normUser(username)}" (${name}).` + (generated ? `\n  Password: ${pw}` : ""));
      break;
    }
    case "passwd": {
      const [username] = pos; if (!username) fail("Usage: passwd <username>");
      const v = loadVault(); const { masterRaw, roster } = await unlock(v);
      const id = await userId(username); const r = roster[normUser(username)];
      if (!v.users[id] || !r) fail(`No account "${normUser(username)}".`);
      const { pw, generated } = await newPassword(username);
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
      const v = loadVault(); const { master, roster } = await unlock(v);
      console.log("Accounts");
      for (const [u, r] of Object.entries(roster)) console.log(`  ${u.padEnd(20)} ${r.name.padEnd(24)} added ${r.added}`);
      console.log("Pages");
      for (const p of await readNav(master, v)) console.log(`  ${p.slug.padEnd(20)} ${p.title.padEnd(24)} ${p.icon}`);
      saveVault(v);
      break;
    }
    case "pages": {
      const v = loadVault(); const { master } = await unlock(v);
      for (const p of await readNav(master, v)) console.log(`${p.slug.padEnd(20)} ${p.title.padEnd(24)} ${p.icon.padEnd(8)} updated ${v.pages[p.id].updated.slice(0, 10)}`);
      saveVault(v);
      break;
    }
    case "add-page": {
      const [slug, title] = pos; if (!slug || !title) fail('Usage: add-page <slug> "<Title>" [--icon=doc] [--after=<slug>]');
      checkSlug(slug); const icon = flags.icon || "doc"; checkIcon(icon);
      const v = loadVault(); const { master } = await unlock(v);
      const nav = await readNav(master, v);
      if (nav.some(p => p.slug === slug)) fail(`A page "${slug}" already exists.`);
      const id = newPageId();
      v.pages[id] = await sealPage(master, id, blankPage(title));
      const at = flags.after ? nav.indexOf(findPage(nav, flags.after)) + 1 : nav.length;
      nav.splice(at, 0, { id, slug, title, icon });
      await writeNav(master, v, nav); saveVault(v);
      console.log(`✔ Added page "${title}" (#/${slug}). Fill it in with open, then seal.`);
      break;
    }
    case "rename-page": {
      const [slug, title] = pos; if (!slug || !title) fail('Usage: rename-page <slug> "<Title>" [--icon=<icon>]');
      const v = loadVault(); const { master } = await unlock(v);
      const nav = await readNav(master, v); const p = findPage(nav, slug);
      p.title = title; if (flags.icon) { checkIcon(flags.icon); p.icon = flags.icon; }
      await writeNav(master, v, nav); saveVault(v);
      console.log(`✔ "${slug}" is now titled "${title}".`);
      break;
    }
    case "remove-page": {
      const [slug] = pos; if (!slug) fail("Usage: remove-page <slug>");
      const v = loadVault(); const { master } = await unlock(v);
      const nav = await readNav(master, v); const p = findPage(nav, slug);
      if (nav.length === 1) fail("That is the only page.");
      delete v.pages[p.id];
      await writeNav(master, v, nav.filter(n => n !== p)); saveVault(v);
      console.log(`✔ Removed page "${p.title}".`);
      break;
    }
    case "open": {
      const v = loadVault(); const { master } = await unlock(v);
      const nav = await readNav(master, v);
      mkdirSync(PLAIN_DIR, { recursive: true });
      writeFileSync(NAV_FILE, JSON.stringify(nav, null, 2) + "\n");
      for (const p of nav) writeFileSync(join(PLAIN_DIR, p.slug + ".html"), await unsealPage(master, v, p.id));
      saveVault(v);
      console.log(`✔ Decrypted ${nav.length} page(s) and the menu into members/_plain/ (git-ignored).\n  Edit the .html files, or nav.json to reorder or retitle, then run seal.`);
      break;
    }
    case "seal": {
      if (!existsSync(NAV_FILE)) fail("Nothing to seal. Run open first.");
      const v = loadVault(); const { master } = await unlock(v);
      const nav = JSON.parse(readFileSync(NAV_FILE, "utf8"));
      const slugs = new Set();
      for (const p of nav) {
        checkSlug(p.slug); checkIcon(p.icon || "doc"); p.icon = p.icon || "doc";
        if (!p.title) fail(`Page "${p.slug}" needs a title.`);
        if (slugs.has(p.slug)) fail(`Two pages share the slug "${p.slug}".`); slugs.add(p.slug);
        if (p.id && !v.pages[p.id]) fail(`nav.json lists an unknown page id for "${p.slug}". Remove the id to make it a new page.`);
      }
      const missing = Object.keys(v.pages).filter(id => !nav.some(p => p.id === id));
      if (missing.length) fail("nav.json leaves out an existing page. Use remove-page to delete pages.");
      let sealed = 0;
      for (const p of nav) {
        const file = join(PLAIN_DIR, p.slug + ".html");
        if (!p.id) p.id = newPageId();
        if (existsSync(file)) { v.pages[p.id] = await sealPage(master, p.id, readFileSync(file, "utf8")); sealed++; }
        else if (!v.pages[p.id]) v.pages[p.id] = await sealPage(master, p.id, blankPage(p.title));
      }
      await writeNav(master, v, nav.map(({ id, slug, title, icon }) => ({ id, slug, title, icon })));
      writeFileSync(NAV_FILE, JSON.stringify(nav, null, 2) + "\n");
      saveVault(v);
      const stray = readdirSync(PLAIN_DIR).filter(f => f.endsWith(".html") && !slugs.has(f.slice(0, -5)));
      console.log(`✔ Sealed ${sealed} page(s) and the menu into members/vault.json. Commit and push vault.json only.` +
        (stray.length ? `\n  Not in the menu, so not sealed: ${stray.join(", ")}` : ""));
      break;
    }
    case "rotate": {
      const v = loadVault(); const { master, roster } = await unlock(v);
      const nav = await readNav(master, v);
      const htmls = {}; for (const p of nav) htmls[p.id] = await unsealPage(master, v, p.id);
      const newRaw = randomBytes(32); const newMaster = await importMaster(newRaw);
      v.users = {}; const issued = [];
      for (const [u, r] of Object.entries(roster)) {
        const pw = generatePassword();
        v.users[await userId(u)] = await makeUserEntry(newRaw, u, r.name, pw);
        issued.push([u, pw]);
      }
      await writeRoster(v, newMaster, roster);
      v.pages = {}; for (const p of nav) v.pages[p.id] = await sealPage(newMaster, p.id, htmls[p.id]);
      await writeNav(newMaster, v, nav);
      saveVault(v);
      console.log("✔ New master key. Every account has a new password:");
      for (const [u, pw] of issued) console.log(`  ${u.padEnd(20)} ${pw}`);
      break;
    }
    default:
      console.log(readFileSync(fileURLToPath(import.meta.url), "utf8").split("\n").slice(1, 37).join("\n").replace(/^ {0,3}/gm, ""));
  }
}
main();
