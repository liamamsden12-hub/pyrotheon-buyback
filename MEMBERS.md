# Members area

`pyrotheonindustries.com/members/` is a username-and-password area. The repo is
public and GitHub Pages has no server, so the members page is **encrypted** in
`members/vault.json`. Only a valid login can decrypt it, in the visitor's
browser. Nothing secret is ever committed in plain text.

## Managing it

Run from the repo root (Node 20+). Each command asks for your own login first.

| Task | Command |
|---|---|
| Add a member | `node tools/members.mjs add <username> "<Display Name>"` (add `--generate` to make up a password) |
| Change a password | `node tools/members.mjs passwd <username>` |
| Remove a member | `node tools/members.mjs remove <username>` |
| List members and pages | `node tools/members.mjs list` |
| Add a sidebar page | `node tools/members.mjs add-page <slug> "<Title>" --icon=chart --after=home` |
| Rename a page or change its icon | `node tools/members.mjs rename-page <slug> "<Title>" --icon=truck` |
| Remove a page | `node tools/members.mjs remove-page <slug>` |
| Edit pages or menu order | `node tools/members.mjs open`, edit `members/_plain/<slug>.html` (or reorder `nav.json`), then `node tools/members.mjs seal` |
| Lock out everyone's old key | `node tools/members.mjs rotate` (issues new passwords to all) |

After any change, commit and push `members/vault.json`. `members/_plain/` is
git-ignored on purpose. Never commit it.

## Limits to know

- No server means no lockout after failed attempts. Someone could download the
  vault and guess passwords offline, so passwords must be 12+ characters.
  Generated ones are 23.
- Removing a member stops their login. A member who dug the unlocked key out of
  their browser could still read later updates until you run `rotate`.
- Each sidebar page is its own HTML document, shown at `/members/#/<slug>`. It
  can hold scripts (dashboards, live ESI market pulls). `{{name}}` becomes the
  signed-in member's name. The menu itself (titles, order) is encrypted too.
- Icons: home, chart, box, truck, flame, doc, users, gear, coins, target.
