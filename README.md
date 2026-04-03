# sentinel

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![vfox plugin](https://img.shields.io/badge/mise-plugin-brightgreen)

A [mise](https://mise.jdx.dev/) plugin that scans staged git diffs for secrets and blocks commits before they reach your repository.

sentinel runs as a `pre-commit` hook. It only scans lines you are about to commit — not your full history — so it is fast and focused.

---

## How it works

1. You install sentinel via mise into your repo.
2. sentinel writes a `pre-commit` hook into `.git/hooks/pre-commit` (chain-safe — it appends if a hook already exists).
3. On every `git commit`, sentinel runs `git diff --cached` and scans only the added lines against a set of secret detection rules.
4. If a match is found the commit is blocked and the finding is printed to stderr with the file, line number, rule name, and a snippet.
5. If no secrets are found, the commit proceeds normally.

---

## What it detects

| Category | Examples |
|---|---|
| AWS | Access Key IDs, Secret Access Keys, Session Tokens |
| GitHub | PATs (classic + fine-grained), OAuth, Actions, Refresh tokens |
| GitLab | PATs (`glpat-`), CI/Deploy tokens (`codeak-`) |
| Google / GCP | API Keys, OAuth Client Secrets |
| Azure | Storage Account Keys |
| Stripe | Live and test secret keys |
| Slack | Bot/user tokens, Webhook URLs |
| SendGrid / Mailgun / Twilio | API keys, Account SIDs |
| Package registries | npm, PyPI, Docker Hub tokens |
| Private keys | PEM, PGP private key blocks |
| JWTs | JSON Web Tokens |
| Generic assignments | `PASSWORD:`, `TOKEN:`, `SECRET:`, `API_KEY:` — quoted or unquoted, in any file type including YAML, `.env`, and shell scripts |

---

## Requirements

- [mise](https://mise.jdx.dev/) installed
- `lua` available on your `PATH`
- Must be run from inside a git repository

---

## Installation

Add sentinel as a mise plugin and install it from inside your repo:

```sh
mise plugin add sentinel https://github.com/Raghuramgrr/mise-sentinel.git
mise install sentinel
```

That's it. sentinel will install itself as a `pre-commit` hook in the current repository.

To verify the hook was installed:

```sh
cat .git/hooks/pre-commit
```

---

## Usage

sentinel runs automatically on every `git commit`. No extra steps needed.

### Bypassing (emergency use only)

If you need to skip the scan for a one-off commit:

```sh
SENTINEL_SKIP=1 git commit -m "your message"
```

Use this sparingly. The intent is to unblock genuine emergencies, not to make bypassing a habit.

### Suppressing false positives

Create a `.sentinel-ignore` file in the root of your repo and add path patterns (Lua patterns) to skip:

```
# .sentinel-ignore
tests/fixtures/
docs/examples%.yaml$
```

Lines starting with `#` are treated as comments. Blank lines are ignored.

---

## Example output

```
+-----------------------------------------------------------------+
|  sentinel: potential secrets detected in staged changes         |
+-----------------------------------------------------------------+

  [CRITICAL]  config/deploy.yaml:14
  rule   : GitLab PAT
  snippet: DEPLOY_TOKEN: glpat-xxxxxxxxxxxxxxxxxxxx

  [HIGH]      .env:3
  rule   : PASSWORD assignment
  snippet: PASSWORD: hunter2

Commit blocked. Options:
  1. Remove the secret and use an environment variable instead.
  2. Add a path pattern to .sentinel-ignore for intentional false positives.
  3. Set SENTINEL_SKIP=1 to bypass (emergency use only).
```

---

## Contributing

Bug reports and rule additions are welcome. Open an issue or a merge request.

When adding a new detection rule, add it to the appropriate category in `scan.lua` and include at least one representative pattern in the PR description so it can be reviewed for false-positive risk.

---

## License

MIT — see [LICENSE](LICENSE).

---

## File structure

```
sentinel/
  metadata.lua              # Plugin name, version, description
  scan.lua                  # The secret scanner (copied into your repo on install)
  hooks/
    available.lua           # Returns the list of installable versions (required by vfox)
    pre_install.lua         # No-op pre-install hook (required by vfox)
    env_keys.lua            # No env vars exposed (required by vfox)
    sentinel_install.lua    # Wires up the pre-commit hook via mise install
LICENSE
README.md
```
