# KeyWatch

[![self-check](https://github.com/bokaranovic/keywatch/actions/workflows/self-check.yml/badge.svg)](https://github.com/bokaranovic/keywatch/actions/workflows/self-check.yml)

**Catch OpenAI & Anthropic API keys before they leak.**

KeyWatch finds exposed API keys - OpenAI (`sk-proj-...`, `sk-svcacct-...`, `sk-admin-...`, legacy `sk-...`) and Anthropic (`sk-ant-...`) - in files, git history, staged changes and your own GitHub repositories. It can scan on demand, watch directories in real time, and **block keys from ever being committed or pushed**.

- Scan - files, directories and full git history (even keys deleted long ago).
- Git hooks - block (or auto-remove) keys on `git commit` and `git push`.
- GitHub Action - fail CI when a key is committed.
- Watch mode - alert to console / Telegram the second a key appears on disk.
- Global stats - how many keys are exposed on GitHub (counts only).
- Privacy by design - keys are never printed or stored in full: output is masked (`sk-proj-AbCdEf...9xYz`) and findings keep only a SHA-256 fingerprint. The GitHub audit only ever looks at *your own* account and never collects other people's keys.

## Requirements

Python 3.8+ - no dependencies. For the GitHub audit: the [`gh` CLI](https://cli.github.com) logged in (`gh auth login`).

## Quick start

```bash
# 0) verify detection works (offline)
python3 keywatch.py selftest              # -> selftest: 10 OK, 0 FAIL

# 1) scan now
python3 keywatch.py scan ~/projects

# 2) install protection into a repo (pre-commit + pre-push hooks)
python3 keywatch.py hook ~/projects/myapp
```

## Commands

| Command | What it does |
|---|---|
| `scan PATH...` | scan files/directories now |
| `watch PATH...` | watch continuously, alert on every new key |
| `git REPO` | scan full git history (all commits, all branches) |
| `gitroot ROOT` | find all `.git` repos under ROOT and scan their history |
| `staged` | scan staged changes (used by the pre-commit hook) |
| `prepush` | scan commits being pushed (used by the pre-push hook) |
| `hook REPO [--redact]` | install pre-commit + pre-push protection |
| `github [USER]` | audit YOUR OWN repos via GitHub code search (other accounts are refused) |
| `stats` | global counts: how many keys are exposed on GitHub |
| `selftest` | verify that detection works |

Exit codes: `0` = clean, `1` = key found (this is what blocks commits/pushes in hooks).

## Git hooks (the important part)

```bash
python3 keywatch.py hook ~/projects/myapp            # block mode
python3 keywatch.py hook ~/projects/myapp --redact   # auto-remove mode
```

- **pre-commit** - scans staged changes before every commit. With `--redact` keys are replaced by `KEY_REMOVED_BY_KEYWATCH`, the file is re-staged and the commit proceeds; without it the commit is blocked.
- **pre-push** - scans every commit that is about to leave your machine (including existing history) and blocks the push if a key is found. If the scan cannot run for some reason, it fails **closed** (blocks).

Existing hooks are backed up as `.bak`.

### GitHub-side protection (server-side, free)

On **public** repositories GitHub's secret scanning and push protection are free - enable them in *Settings -> Code security*. GitHub then rejects pushes containing recognized provider keys and notifies the provider (OpenAI and Anthropic participate), who can revoke the key automatically.

## GitHub Action

```yaml
name: KeyWatch
on: [push, pull_request]
jobs:
  keywatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # full history so the history scan works
      - uses: bokaranovic/keywatch@main
```

## Watch mode + Telegram alerts

```bash
python3 keywatch.py watch ~/projects --interval 10
```

Alerts also go to Telegram when a bot is configured: set `KEYWATCH_TG_BOT_TOKEN` and `KEYWATCH_TG_CHAT_ID` (falls back to `TELEGRAM_BOT_TOKEN` / `TELEGRAM_HOME_CHANNEL`, and reads a local Hermes `.env`).

## What it detects

| Type | Formats |
|---|---|
| OpenAI | `sk-proj-...`, `sk-svcacct-...`, `sk-admin-...`, legacy `sk-...` (48 chars) |
| Anthropic | `sk-ant-api03-...`, `sk-ant-admin01-...`, `sk-ant-oat01-...` |
| .env / config | `OPENAI_API_KEY=...`, `ANTHROPIC_API_KEY: "..."`, including JSON style (medium confidence) |

Placeholders are ignored (`sk-xxxx...`, `sk-ant-your-key-here`, `$OPENAI_API_KEY`, `<insert-key>`, documentation examples). Use a `keywatch.ignore` file (globs, one per line) or `--ignore "glob"` to silence specific paths.

## GitHub audit (your own repos only)

```bash
python3 keywatch.py github            # base queries + per-file-type sweep (*.xml *.json *.properties *.sql *.txt *.log *.tmp *.bak)
python3 keywatch.py github --quick    # fast pass
```

Every hit is verified by fetching the file and scanning it with the same detector: you get **REAL KEY?** vs **mention only (placeholder/docs)**. GitHub's code search API is rate-limited to 10 queries/min, so the full run paces itself (~7 s between queries, ~6 min total) and auto-pauses on rate limits.

## Global stats (counts only)

```bash
python3 keywatch.py stats
```

Sends COUNT queries only - no key is ever fetched, displayed or collected. Useful to show how much is exposed in the wild.

## Security & privacy

- Never prints or stores full keys - masked output + SHA-256 fingerprint only.
- The GitHub audit searches only the authenticated account; targeting other accounts is refused.
- No telemetry. The only network calls are GitHub CLI calls and your optional Telegram alert.

## License

MIT - see [LICENSE](LICENSE).
