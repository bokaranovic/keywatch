#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KEYWATCH - detect OpenAI / Anthropic API keys before they leak.

Finds API keys in files, git history, staged changes and your GitHub
account. Can watch directories and alert on every new key.

  scan PATH...     scan files/directories now
  watch PATH...    watch continuously; alert on every new key
  git REPO         scan full git history (all commits, all branches)
  gitroot ROOT     find all .git repos under ROOT and scan their history
  staged           scan staged changes (used by the pre-commit hook)
  hook REPO        install pre-commit + pre-push protection (--redact = auto-remove)
  prepush          scan commits being pushed (used by the pre-push hook)
  github [USER]    audit YOUR OWN repos via GitHub code search (rejects others)
  stats            GLOBAL counts: how many keys are exposed on GitHub
  selftest         verify that detection works

Keys are NEVER printed in full - only masked (e.g. sk-proj-AbCdEf...9xYz).
Findings are logged to keywatch.log (JSONL).

Exit codes: 0 = clean, 1 = key found (used to block commit/push).
"""
import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime

VERSION = "1.2"
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOG = os.path.join(HERE, "keywatch.log")

# ---------------------------------------------------------------- detekcija
TOKEN_PATTERNS = [
    ("openai", "high", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}")),
    ("openai", "high", re.compile(r"\bsk-[A-Za-z0-9]{40,}")),
    ("anthropic", "high", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
]
ENV_PATTERN = re.compile(
    r"\b(OPENAI_API_KEY|ANTHROPIC_API_KEY|OPENAI_KEY|ANTHROPIC_KEY)\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_-]{20,})",
    re.IGNORECASE,
)
ENV_PROVIDER = {
    "OPENAI_API_KEY": "openai", "OPENAI_KEY": "openai",
    "ANTHROPIC_API_KEY": "anthropic", "ANTHROPIC_KEY": "anthropic",
}
PLACEHOLDER_WORDS = (
    "xxxx", "your", "example", "dummy", "fake", "sample", "placeholder",
    "changeme", "redacted", "abcdefghijk", "test-key", "test_key", "testkey",
    "notreal", "replace-me",
)

GH_TERMS = ["sk-proj-", "sk-svcacct-", "sk-admin-", "sk-ant-",
            "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]
# Tipovi fajlova koji se automatski pretrazuju na GitHubu (kao dork sa slike)
GH_RISKY_EXTS = ["xml", "json", "properties", "sql", "txt", "log", "tmp", "bak"]

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build", ".next",
    ".nuxt", ".cache", "site-packages", ".idea", ".vs", ".gradle", ".cargo",
    "target", ".tox", ".eggs",
}
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff",
    ".pdf", ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".tar", ".exe",
    ".dll", ".so", ".dylib", ".bin", ".msi", ".class", ".jar", ".pyc", ".pyo",
    ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".wav", ".flac", ".ogg", ".opus",
    ".onnx", ".pt", ".pth", ".safetensors", ".gguf", ".whl", ".db", ".sqlite",
    ".sqlite3", ".vhd", ".vhdx", ".iso", ".woff", ".woff2", ".ttf", ".otf",
    ".asar", ".parquet", ".npy", ".npz", ".fig",
}


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def mask_key(secret):
    if len(secret) > 26:
        return secret[:14] + "\u2026" + secret[-4:]
    return secret[:6] + "\u2026"


def fingerprint(secret):
    return hashlib.sha256(secret.encode("utf-8", "ignore")).hexdigest()[:16]


def looks_placeholder(secret):
    s = secret.lower()
    if any(w in s for w in PLACEHOLDER_WORDS):
        return True
    if len(set(secret)) < 12:
        return True
    if not (any(c.isdigit() for c in secret) and any(c.isalpha() for c in secret)):
        return True
    return False


def detect_in_line(line):
    """Vrati listu pogodaka: provider, confidence, secret, span."""
    hits = []
    token_spans = []
    for provider, conf, rx in TOKEN_PATTERNS:
        for m in rx.finditer(line):
            secret = m.group(0)
            if looks_placeholder(secret):
                continue
            token_spans.append(m.span(0))
            hits.append({"provider": provider, "confidence": conf,
                         "secret": secret, "span": m.span(0)})
    for m in ENV_PATTERN.finditer(line):
        var = m.group(1).upper()
        value = m.group(2)
        span = m.span(2)
        if any(not (span[1] <= a or span[0] >= b) for a, b in token_spans):
            continue  # isti tekst je već uhvaćen kao token
        if looks_placeholder(value) or value.upper() == var:
            continue
        hits.append({"provider": ENV_PROVIDER.get(var, "nepoznat"),
                     "confidence": "medium", "secret": value, "span": span})
    return hits


def redact(line, hits):
    out = line
    for h in sorted(hits, key=lambda x: x["span"][0], reverse=True):
        a, b = h["span"]
        out = out[:a] + mask_key(h["secret"]) + out[b:]
    return out.strip()


# ---------------------------------------------------------------- fajlovi
def iter_files(target, ignores=(), max_size=2 * 1024 * 1024):
    if os.path.isfile(target):
        yield target
        return
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if os.path.splitext(fn)[1].lower() in SKIP_EXTS:
                continue
            rel = os.path.relpath(p, target)
            if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(fn, g) for g in ignores):
                continue
            try:
                if os.path.getsize(p) > max_size:
                    continue
            except OSError:
                continue
            yield p


def scan_file(path, source, extra=None):
    """Skeniraj jedan fajl; vrati listu nalaza (dict)."""
    findings = []
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192)
            if b"\x00" in head:
                return findings
            fh.seek(0)
            data = fh.read()
    except OSError:
        return findings
    text = data.decode("utf-8", "ignore")
    for ln, line in enumerate(text.splitlines(), 1):
        hits = detect_in_line(line)
        for h in hits:
            rec = {
                "ts": now_iso(), "source": source, "provider": h["provider"],
                "confidence": h["confidence"], "masked": mask_key(h["secret"]),
                "fp": fingerprint(h["secret"]), "file": path, "line": ln,
                "snippet": redact(line, hits),
            }
            if extra:
                rec.update(extra)
            findings.append(rec)
    return findings


def fmt_finding(rec):
    loc = str(rec.get("file", "?"))
    if rec.get("line"):
        loc += ":" + str(rec["line"])
    if rec.get("commit"):
        loc += "  (commit " + rec["commit"][:10]
        if rec.get("author"):
            loc += ", " + rec["author"]
        if rec.get("date"):
            loc += ", " + str(rec["date"])[:10]
        loc += ")"
    return "  [%s/%s] %s  %s" % (rec["provider"], rec["confidence"], loc, rec["masked"])


# ---------------------------------------------------------------- log / alarm
class Log(object):
    def __init__(self, path):
        self.path = path

    def add(self, rec):
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError as exc:
            print("  ! cannot write log: %s" % exc, file=sys.stderr)

    def load_pairs(self):
        pairs = set()
        try:
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        o = json.loads(line)
                    except ValueError:
                        continue
                    if o.get("fp"):
                        pairs.add("%s|%s" % (o["fp"], o.get("file", "")))
        except OSError:
            pass
        return pairs


def _load_env_file():
    """Ucitaj TELEGRAM_* iz hermes .env ako vec nisu u okruzenju."""
    cands = [
        os.environ.get("KEYWATCH_ENV_FILE"),
        os.path.join(os.path.expanduser("~"), "AppData", "Local", "hermes", ".env"),
        os.path.expanduser("~/.hermes/.env"),
    ]
    for cand in cands:
        if not cand or not os.path.exists(cand):
            continue
        try:
            with open(cand, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip().strip('"').strip("'")
                    if k and k not in os.environ:
                        os.environ[k] = v
        except OSError:
            pass
        return


def tg_config():
    token = os.environ.get("KEYWATCH_TG_BOT_TOKEN") or os.environ.get("TELEGRAM_BOT_TOKEN")
    chat = (os.environ.get("KEYWATCH_TG_CHAT_ID") or os.environ.get("TELEGRAM_HOME_CHANNEL")
            or os.environ.get("TELEGRAM_CHAT_ID"))
    return token, chat


def tg_send(text):
    token, chat = tg_config()
    if not token or not chat:
        return False
    try:
        payload = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
        with urllib.request.urlopen(
                "https://api.telegram.org/bot%s/sendMessage" % token,
                data=payload, timeout=15) as resp:
            return resp.status == 200
    except Exception:
        return False


def load_ignores(args):
    ignores = list(getattr(args, "ignore", []) or [])
    f = os.path.join(HERE, "keywatch.ignore")
    if os.path.exists(f):
        try:
            with open(f, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ignores.append(line)
        except OSError:
            pass
    return ignores


# ---------------------------------------------------------------- komande
def cmd_scan(args):
    ignores = load_ignores(args)
    max_b = int(args.max_size * 1024 * 1024)
    log = Log(args.log)
    total = 0
    for target in args.paths:
        if not os.path.exists(target):
            print("  ! does not exist: %s" % target)
            continue
        print("\nScanning: %s" % target)
        n = 0
        for path in iter_files(target, ignores, max_b):
            for rec in scan_file(path, "scan"):
                print(fmt_finding(rec))
                log.add(rec)
                n += 1
        print("  OK - no findings" if n == 0 else "  FINDINGS: %d" % n)
        total += n
    print("\nKEYWATCH: %d finding(s) total (log: %s)" % (total, args.log))
    return 1 if total else 0


def cmd_watch(args):
    ignores = load_ignores(args)
    max_b = int(args.max_size * 1024 * 1024)
    log = Log(args.log)
    known = log.load_pairs()
    state = {}
    print("KEYWATCH watch - interval %ss%s" % (
        args.interval, ", duration %ss" % args.duration if args.duration else " (Ctrl+C to stop)"))
    token, chat = tg_config()
    print("Telegram: %s" % ("ENABLED" if (token and chat)
                            else "disabled (set KEYWATCH_TG_BOT_TOKEN and KEYWATCH_TG_CHAT_ID)"))
    baseline = 0
    for t in args.paths:
        for p in iter_files(t, ignores, max_b):
            try:
                st = os.stat(p)
            except OSError:
                continue
            state[p] = (st.st_mtime_ns, st.st_size)
            for rec in scan_file(p, "watch-baseline"):
                pair = "%s|%s" % (rec["fp"], rec["file"])
                if pair in known:
                    continue
                known.add(pair)
                baseline += 1
                if args.alert_existing:
                    print("ALERT (existing):" + fmt_finding(rec))
                    log.add(rec)
                    tg_send("KEYWATCH (existing): %s key\n%s:%s\n%s" % (
                        rec["provider"], rec["file"], rec.get("line", "?"), rec["masked"]))
    print("Baseline: %d key(s) already present - not alerting.\n" % baseline)
    start = time.time()
    try:
        while True:
            time.sleep(args.interval)
            for t in args.paths:
                for p in iter_files(t, ignores, max_b):
                    try:
                        st = os.stat(p)
                    except OSError:
                        continue
                    key = (st.st_mtime_ns, st.st_size)
                    prev = state.get(p)
                    state[p] = key
                    if prev == key:
                        continue
                    for rec in scan_file(p, "watch"):
                        pair = "%s|%s" % (rec["fp"], rec["file"])
                        if pair in known:
                            continue
                        known.add(pair)
                        print("[ALARM] %s%s" % (now_iso(), fmt_finding(rec)))
                        log.add(rec)
                        ok = tg_send("KEYWATCH ALERT: %s key\n%s:%s\n%s" % (
                            rec["provider"], rec["file"], rec.get("line", "?"), rec["masked"]))
                        if ok:
                            print("         (sent to Telegram)")
            if args.duration and (time.time() - start) >= args.duration:
                print("\nWatch finished (duration elapsed).")
                return 0
    except KeyboardInterrupt:
        print("\nWatch interrupted (Ctrl+C).")
        return 0


def _check_repo(repo):
    try:
        subprocess.check_output(["git", "-C", repo, "rev-parse", "--git-dir"],
                                stderr=subprocess.DEVNULL, text=True)
        return True
    except Exception:
        return False


def _history_findings(repo, revs=("--all",), err=None):
    """Generator: nalazi iz git historije (default: sve grane).
    Ako je dat `err` dict, upisuje rc iz `git log` (0 = ok)."""
    cmd = (["git", "-C", repo, "log"] + list(revs) +
           ["-p", "-U0", "--no-color",
            "--date=iso", "--pretty=format:@@KW@@%H|%an|%ad|%s"])
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace", bufsize=1)
    cur = {"commit": "", "author": "", "date": ""}
    curfile = None
    for line in proc.stdout:
        line = line.rstrip("\n")
        if line.startswith("@@KW@@"):
            parts = line[6:].split("|", 3)
            cur = {"commit": parts[0],
                   "author": parts[1] if len(parts) > 1 else "",
                   "date": parts[2] if len(parts) > 2 else ""}
            continue
        if line.startswith("+++ b/"):
            curfile = line[6:]
            continue
        if line.startswith("+++ /dev/null"):
            curfile = None
            continue
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            hits = detect_in_line(content)
            for h in hits:
                yield {
                    "ts": now_iso(), "source": "git", "provider": h["provider"],
                    "confidence": h["confidence"], "masked": mask_key(h["secret"]),
                    "fp": fingerprint(h["secret"]),
                    "file": os.path.join(repo, curfile) if curfile else "?",
                    "line": "", "snippet": redact(content, hits),
                    "commit": cur["commit"], "author": cur["author"],
                    "date": cur["date"],
                }
    proc.wait()
    if err is not None:
        err["rc"] = proc.returncode


def _rev_exists(repo, rev):
    r = subprocess.run(["git", "-C", repo, "cat-file", "-e", rev + "^{commit}"],
                       capture_output=True)
    return r.returncode == 0


def cmd_git(args):
    repo = args.repo
    if not _check_repo(repo):
        print("Not a git repo: %s" % repo)
        return 2
    log = Log(args.log)
    print("Git history: %s" % os.path.abspath(repo))
    total = 0
    err = {}
    for rec in _history_findings(repo, err=err):
        print(fmt_finding(rec))
        log.add(rec)
        total += 1
    if err.get("rc"):
        print("  ! warning: git log exited with rc=%d (result may be incomplete)" % err["rc"])
    print("\nGit history: %d finding(s)" % total)
    return 1 if total else 0


def cmd_gitroot(args):
    root = args.root
    repos = []
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirnames:
            repos.append(dirpath)
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    print("Repos found: %d" % len(repos))
    log = Log(args.log)
    total = 0
    for repo in repos:
        n = 0
        for rec in _history_findings(repo):
            print(fmt_finding(rec))
            log.add(rec)
            n += 1
            total += 1
        if n:
            print("  ^ repo: %s - %d finding(s)" % (repo, n))
    print("\nTotal findings in history: %d" % total)
    return 1 if total else 0


REDACT_PLACEHOLDER = "UKLONJENO_KEYWATCH"


def _staged_scan(repo):
    """Vrati (nalazi, mapa fajl->skup_kljuceva, greska)."""
    cmd = ["git", "-C", repo, "diff", "--cached", "-U0", "--no-color"]
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        return [], {}, (r.stderr or "").strip()[:200]
    curfile = None
    findings = []
    redactions = {}
    for line in r.stdout.splitlines():
        if line.startswith("+++ b/"):
            curfile = line[6:]
            continue
        if line.startswith("+++ /dev/null"):
            curfile = None
            continue
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            hits = detect_in_line(content)
            for h in hits:
                findings.append({
                    "ts": now_iso(), "source": "staged", "provider": h["provider"],
                    "confidence": h["confidence"], "masked": mask_key(h["secret"]),
                    "fp": fingerprint(h["secret"]),
                    "file": curfile or "?", "line": "",
                    "snippet": redact(content, hits)})
                if curfile:
                    redactions.setdefault(curfile, set()).add(h["secret"])
    return findings, redactions, None


def cmd_staged(args):
    repo = getattr(args, "repo", ".") or "."
    log = Log(args.log)
    findings, redactions, err = _staged_scan(repo)
    if err:
        print("  ! git error: %s" % err)
        return 0  # ne blokiraj commit zbog nase greske
    for rec in findings:
        print(fmt_finding(rec))
        log.add(rec)
    if not findings:
        return 0
    if getattr(args, "redact", False):
        fixed = 0
        for fname in sorted(redactions):
            fpath = os.path.join(repo, fname)
            try:
                txt = open(fpath, encoding="utf-8", errors="replace", newline="").read()
            except OSError:
                continue
            new = txt
            for secret in redactions[fname]:
                new = new.replace(secret, REDACT_PLACEHOLDER)
            if new == txt:
                continue
            try:
                with open(fpath, "w", encoding="utf-8", newline="") as fh:
                    fh.write(new)
            except OSError:
                continue
            subprocess.run(["git", "-C", repo, "add", "--", fname],
                           capture_output=True, text=True)
            print("  REMOVED from file: %s" % fname)
            fixed += 1
        if fixed:
            again, _, err2 = _staged_scan(repo)
            if not again:
                print("\nKeys automatically removed and files re-staged - the commit may proceed.")
                print("NOTE: if the key was real, REVOKE it and keep it in a .env file outside the repo.")
                return 0
            print("\nBLOCKED: findings remain even after removal - commit aborted.")
            return 1
    print("\nBLOCKED: %d OpenAI/Anthropic key(s) in staged changes! Commit aborted."
          "\nFix: keywatch.py staged --redact (auto-remove) or remove manually "
          "and keep the key in a .env outside the repo." % len(findings))
    return 1


def cmd_prepush(args):
    repo = getattr(args, "repo", ".") or "."
    if not _check_repo(repo):
        print("Not a git repo: %s" % repo)
        return 2
    raw = ""
    try:
        if not sys.stdin.isatty():
            raw = sys.stdin.read()
    except Exception:
        raw = ""
    pairs = []
    for line in (raw or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local_sha, remote_sha = parts[1], parts[3]
        if not local_sha or not any(c != "0" for c in local_sha):
            continue
        pairs.append((local_sha, remote_sha))
    if not pairs:
        pairs = [(None, None)]  # manual run: scan commits not on any remote
    log = Log(args.log)
    total = 0
    scans_failed = 0
    for local_sha, remote_sha in pairs:
        if local_sha is None:
            revs = ["HEAD", "--not", "--remotes"]
        elif (remote_sha and any(c != "0" for c in remote_sha)
                and _rev_exists(repo, remote_sha)):
            revs = ["%s..%s" % (remote_sha, local_sha)]
        else:
            # remote ref ne postoji lokalno (ili je novi branch) -> skeniraj
            # CIJELU historiju koja se salje (sigurnije od praznog skena)
            revs = [local_sha]
        err = {}
        for rec in _history_findings(repo, revs, err):
            print(fmt_finding(rec))
            log.add(rec)
            total += 1
        if err.get("rc"):
            scans_failed += 1
    if total:
        print("\nBLOCKED: %d key(s) in commits being pushed - push aborted." % total)
        print("If the key is real: REVOKE it. Clean the history (git rebase -i / git filter-repo) "
              "or deliberately push with --no-verify.")
        return 1
    if scans_failed:
        print("\nBLOCKED: git log scan failed (%d range(s)) - cannot verify the push."
              " Use --no-verify to override deliberately." % scans_failed)
        return 1
    return 0


def cmd_hook(args):
    repo = os.path.abspath(args.repo)
    if not _check_repo(repo):
        print("Not a git repo: %s" % repo)
        return 2
    gitdir = subprocess.check_output(["git", "-C", repo, "rev-parse", "--git-dir"],
                                     text=True).strip()
    if not os.path.isabs(gitdir):
        gitdir = os.path.join(repo, gitdir)
    hooks_dir = os.path.join(gitdir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    py = (sys.executable or "python").replace("\\", "/")
    script = os.path.abspath(__file__).replace("\\", "/")
    wanted = [("pre-commit",
               '"%s" "%s" staged%s' % (py, script, " --redact" if args.redact else ""),
               "block/remove keys on commit")]
    if not getattr(args, "no_prepush", False):
        wanted.append(("pre-push",
                       '"%s" "%s" prepush' % (py, script),
                       "block push of commits containing keys"))
    for name, cmdline, desc in wanted:
        target = os.path.join(hooks_dir, name)
        if os.path.exists(target):
            try:
                with open(target, encoding="utf-8", errors="replace") as fh:
                    existing = fh.read()
            except OSError:
                existing = ""
            if "KEYWATCH" not in existing:
                bak = target + ".bak"
                if os.path.exists(bak):
                    print("  ! %s exists and holds a foreign hook - skipping." % bak)
                    continue
                os.replace(target, bak)
                print("Existing hook backed up: %s" % bak)
        body = ("#!/bin/sh\n"
                "# KEYWATCH %s: %s\n"
                "%s || exit 1\n" % (name, desc, cmdline))
        with open(target, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)
        try:
            os.chmod(target, 0o755)
        except OSError:
            pass
        print("Hook installed: %s" % target)
    return 0


def _gh_raw(args_list):
    return subprocess.run(["gh"] + args_list, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def _gh_login():
    r = _gh_raw(["api", "user", "--jq", ".login"])
    if r.returncode != 0:
        return None, (r.stderr or r.stdout or "").strip()[:300]
    return r.stdout.strip(), None


def _search_code(user, term, ext=None, per_page=100):
    q = term + (" extension:" + ext if ext else "")
    if user:
        q += " user:" + user
    r = _gh_raw(["api", "-X", "GET", "search/code", "-f", "q=" + q,
                 "-f", "per_page=%d" % per_page])
    if r.returncode != 0:
        msg = (r.stderr or r.stdout or "").strip()
        if "rate limit" in msg.lower():
            return None, "RATE_LIMIT"
        return None, msg[:200]
    try:
        data = json.loads(r.stdout or "{}")
    except ValueError:
        return None, 0, "ne mogu da parsiram odgovor"
    return (data.get("items") or []), data.get("total_count", 0), None


def _fetch_file(repo_full, path):
    url = "repos/%s/contents/%s" % (repo_full, urllib.parse.quote(path, safe="/"))
    r = _gh_raw(["api", "-H", "Accept: application/vnd.github.raw", url])
    if r.returncode != 0:
        msg = (r.stderr or r.stdout or "").strip().replace("\n", " ")
        return None, (msg[-140:] if msg else "gh greska")
    return r.stdout, None


def _verify_content(text):
    """Skeniraj sadrzaj fajla sa GitHub-a: stvarni kljuc ili samo pominjanje."""
    hits = []
    for ln, line in enumerate((text or "").splitlines(), 1):
        for h in detect_in_line(line):
            hits.append({"line": ln, "provider": h["provider"],
                         "confidence": h["confidence"],
                         "masked": mask_key(h["secret"]),
                         "fp": fingerprint(h["secret"])})
            if len(hits) >= 5:
                return hits
    return hits


def cmd_github(args):
    own, err = _gh_login()
    if not own:
        print("gh CLI is not available/logged in. Run: gh auth login")
        if err:
            print(err)
        return 2
    user = args.user or own
    if user.lower() != own.lower():
        print("ERROR: KeyWatch searches only your own account (%s), never others'." % own)
        print("Collecting other people's API keys is deliberately NOT supported.")
        return 2
    exts = [e.strip().lstrip("*.").lower()
            for e in (args.exts or "").split(",") if e.strip()]
    queries = [(t, None) for t in GH_TERMS]
    if not args.quick and exts:
        for t in GH_TERMS:
            for e in exts:
                queries.append((t, e))
    print("GitHub code search - user: %s" % user)
    print("Terms: %s" % ", ".join(GH_TERMS))
    if args.quick or not exts:
        print("Mode: QUICK (base queries only, all file types)")
    else:
        print("File types (automatic queries): %s" % ", ".join("*." + e for e in exts))
        print("Queries: %d | pacing %.0fs -> est. ~%.0f min" % (
            len(queries), args.pace, len(queries) * args.pace / 60.0))
    hits = {}
    for i, (term, ext) in enumerate(queries, 1):
        label = term + (" extension:" + ext if ext else "")
        items, tcount, err = _search_code(user, term, ext)
        if err == "RATE_LIMIT":
            print("  [%d/%d] %-42s rate limit - pausing 75s..." % (i, len(queries), label))
            time.sleep(75)
            items, tcount, err = _search_code(user, term, ext)
        if err:
            print("  [%d/%d] %-42s ERROR: %s" % (i, len(queries), label, err))
        else:
            new = 0
            for it in items:
                url = it.get("html_url") or it.get("url")
                if not url or url in hits:
                    continue
                repo = it.get("repository") or {}
                name = (repo.get("full_name") if isinstance(repo, dict) else str(repo)) or "?"
                hits[url] = {"repo": name, "path": it.get("path") or "?",
                             "url": it.get("html_url") or url,
                             "found_by": label}
                new += 1
            print("  [%d/%d] %-42s hits: %-4d (new: %d)" % (
                i, len(queries), label, tcount or len(items), new))
        if i < len(queries) and args.pace:
            time.sleep(args.pace)
    if not hits:
        print("\nNo hits.")
        return 0
    log = Log(args.log)
    real = 0
    verified = 0
    risky = 0
    real_urls = []
    ordered = sorted(hits.values(),
                     key=lambda h: (os.path.splitext(h["path"])[1].lstrip(".").lower()
                                    not in exts, h["repo"], h["path"]))
    print("\n=== HITS (%d unique files) ===" % len(hits))
    for h in ordered:
        ext = os.path.splitext(h["path"])[1].lstrip(".").lower()
        mark = "!" if ext in exts else "."
        if ext in exts:
            risky += 1
        info = "(verification off)"
        if args.verify and verified < args.fetch_limit:
            verified += 1
            content, ferr = _fetch_file(h["repo"], h["path"])
            if content is None:
                info = "verification failed (%s)" % ferr
            else:
                vhits = _verify_content(content)
                if vhits:
                    real += 1
                    v = vhits[0]
                    info = "REAL KEY?: %s %s (line %s)" % (
                        v["provider"], v["masked"], v["line"])
                    real_urls.append(h["url"])
                    log.add({"ts": now_iso(), "source": "github",
                             "provider": v["provider"], "confidence": v["confidence"],
                             "masked": v["masked"], "fp": v["fp"],
                             "file": h["url"], "line": v["line"],
                             "snippet": "GitHub: %s" % h["url"]})
                else:
                    info = "mention only (placeholder/docs)"
        print("  [%s] .%-10s %s/%s\n        -> %s\n        %s" % (
            mark, ext, h["repo"], h["path"], info, h["url"]))
    print("\nTotal files: %d | in risky file types (%s): %d | with a real key: %d" % (
        len(hits), ",".join(exts) if exts else "-", risky, real))
    if real:
        tg_send("KEYWATCH GitHub: %d file(s) with a real key!\n%s" % (
            real, "\n".join(real_urls[:5])))
        return 1
    if not args.verify and hits:
        return 1
    return 0


def _fx(*parts):
    """Sastavi test-string u runtime-u (da sam fajl ostane 'cist' za skenere)."""
    return "".join(parts)


def cmd_selftest(args):
    o, a, l = "sk-" + "proj-", "sk-" + "ant-api03-", "sk-"
    cases = [
        ('client = OpenAI(api_key="%s")'
         % _fx(o, "T3BlbkFJ", "qX7b2K9mLpQ4vRtY8wZnA6cD1eF5gH2iJ4kL7mN0p"), True),
        ("API_KEY='%s'"
         % _fx(a, "Ab3XyK9mPq2", "Rt5Vw8ZnQ1cD4eF7gH0iJ3kL6mN9oP2qR5sT8uV1wX4yZ7"), True),
        ('LEGACY = "%s"'
         % _fx(l, "9fXk2LqA7mP4rT8vW1yZ3bD6gH0jN5sU2cE8iK4oL7qR1aM5"), True),
        ("OPENAI_API_KEY=%s"
         % _fx("gw-", "7f3a9c2e5b8d1f4a6c9e2b5d8f1a4c7e"), True),
        ('CONFIG = {"ANTHROPIC_API_KEY": "%s"}'
         % _fx("ant-", "9k2m4p6r8t0v2x4z6b8d0f2h4j6l8n0p"), True),
        ('OPENAI_API_KEY = "%s"' % _fx(l, "x" * 32), False),
        ('ANTHROPIC_API_KEY = "%s"' % _fx("sk-ant-", "your-key-here"), False),
        ('key = os.environ["OPENAI_API_KEY"]', False),
        ('TEMPLATE = "OPENAI_API_KEY=<insert-key>"', False),
        ('DOC = "%s"' % _fx(o, "abcdefghijklmnopqrstuvwxyz", "0123456789"), False),
    ]
    ok = bad = 0
    for line, expected in cases:
        got = bool(detect_in_line(line))
        mark = "OK " if got == expected else "FAIL"
        if got == expected:
            ok += 1
        else:
            bad += 1
            print("  %s %s  (expected %s)" % (mark, line[:70], expected))
    print("selftest: %d OK, %d FAIL" % (ok, bad))
    return 1 if bad else 0


def cmd_stats(args):
    """GLOBALNA statistika: samo brojevi iz GitHub pretrage (nista se ne skida)."""
    terms = [t.strip() for t in (args.terms or "").split(",") if t.strip()]
    exts = [e.strip().lstrip("*.").lower() for e in (args.exts or "").split(",") if e.strip()]
    ext_term = args.ext_term or (terms[0] if terms else "")
    queries = [(t, None) for t in terms]
    if exts and ext_term:
        queries += [(ext_term, e) for e in exts]
    print("KEYWATCH stats - global counts from GitHub (counts only, no key is ever fetched)")
    print("Upita: %d | pacing %.0fs -> ~%.0f min\n" % (
        len(queries), args.pace, len(queries) * args.pace / 60.0))
    for i, (term, ext) in enumerate(queries, 1):
        label = term + (" extension:" + ext if ext else "")
        items, tcount, err = _search_code(None, term, ext, per_page=1)
        if err == "RATE_LIMIT":
            time.sleep(75)
            items, tcount, err = _search_code(None, term, ext, per_page=1)
        if err:
            print("  %-44s error: %s" % (label, err))
        else:
            print("  %-44s files: %s" % (label, tcount))
        if i < len(queries) and args.pace:
            time.sleep(args.pace)
    print("\nNote: numbers come from the GitHub legacy code search API - approximate/limited.")
    return 0


# ---------------------------------------------------------------- main
def add_log(sp):
    # SUPPRESS: ako --log nije dat na podkomandi, ne diraj vrijednost iz
    # glavnog parsera (argparse bi je inace prepisao defaultom)
    sp.add_argument("--log", default=argparse.SUPPRESS,
                    help="JSONL file for findings (default: next to the script)")


def add_common(sp):
    sp.add_argument("--log", default=argparse.SUPPRESS,
                    help="JSONL file for findings (default: next to the script)")
    sp.add_argument("paths", nargs="*", default=["."],
                    help="file(s) or directories (default: current directory)")
    sp.add_argument("--ignore", action="append", default=[],
                    help="glob to skip (repeatable)")
    sp.add_argument("--max-size", type=float, default=2.0,
                    help="max file size in MB (default 2)")


def build_parser():
    p = argparse.ArgumentParser(
        prog="keywatch",
        description="KEYWATCH - detect OpenAI/Anthropic API keys in files, "
                    "git history and on GitHub.")
    p.add_argument("--version", action="version", version="KEYWATCH " + VERSION)
    p.add_argument("--log", default=DEFAULT_LOG,
                   help="JSONL file for findings (default: next to the script)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="scan files/directories now")
    add_common(sp)
    sp.set_defaults(func=cmd_scan)

    wp = sub.add_parser("watch", help="watch directories and alert on every new key")
    add_common(wp)
    wp.add_argument("--interval", type=float, default=10, help="seconds between checks")
    wp.add_argument("--duration", type=float, default=0,
                    help="auto-stop after N seconds (0 = forever)")
    wp.add_argument("--alert-existing", action="store_true",
                    help="also alert for keys already present at start")
    wp.set_defaults(func=cmd_watch)

    gp = sub.add_parser("git", help="scan git history (all commits)")
    gp.add_argument("repo", nargs="?", default=".", help="path to the git repo")
    add_log(gp)
    gp.set_defaults(func=cmd_git)

    gr = sub.add_parser("gitroot", help="find all .git repos under ROOT and scan their history")
    gr.add_argument("root")
    add_log(gr)
    gr.set_defaults(func=cmd_gitroot)

    st = sub.add_parser("staged", help="scan staged changes (used by the pre-commit hook)")
    st.add_argument("--repo", default=".")
    st.add_argument("--redact", action="store_true",
                    help="automatically remove found keys from files and re-stage")
    add_log(st)
    st.set_defaults(func=cmd_staged)

    pp = sub.add_parser("prepush", help="scan commits being pushed (used by the pre-push hook)")
    pp.add_argument("--repo", default=".")
    add_log(pp)
    pp.set_defaults(func=cmd_prepush)

    hk = sub.add_parser("hook", help="install pre-commit + pre-push protection")
    hk.add_argument("repo", nargs="?", default=".")
    hk.add_argument("--no-prepush", action="store_true",
                    help="pre-commit only (no pre-push)")
    hk.add_argument("--redact", action="store_true",
                    help="pre-commit auto-removes keys instead of blocking")
    add_log(hk)
    hk.set_defaults(func=cmd_hook)

    gh = sub.add_parser("github", help="audit your own repos via GitHub code search (gh CLI)")
    gh.add_argument("user", nargs="?", default=None)
    gh.add_argument("--quick", action="store_true",
                    help="base queries only (no per-file-type queries)")
    gh.add_argument("--exts", default=",".join(GH_RISKY_EXTS),
                    help="file types for automatic queries (default: %s)" % ",".join(GH_RISKY_EXTS))
    gh.add_argument("--pace", type=float, default=7.0,
                    help="seconds between queries (GitHub limit: 10/min) (default 7)")
    gh.add_argument("--no-verify", dest="verify", action="store_false",
                    help="do not fetch file contents for verification")
    gh.add_argument("--fetch-limit", type=int, default=50,
                    help="max files to fetch for verification (default 50)")
    add_log(gh)
    gh.set_defaults(func=cmd_github)

    stx = sub.add_parser("stats", help="GLOBAL counts: how many keys are exposed on GitHub")
    stx.add_argument("--terms", default=",".join(GH_TERMS))
    stx.add_argument("--exts", default=",".join(GH_RISKY_EXTS))
    stx.add_argument("--ext-term", default=None,
                     help="term to break down by file type (default: first)")
    stx.add_argument("--pace", type=float, default=7.0)
    stx.set_defaults(func=cmd_stats)

    sft = sub.add_parser("selftest", help="verify that detection works")
    add_log(sft)
    sft.set_defaults(func=cmd_selftest)
    return p


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    args = build_parser().parse_args(argv)
    _load_env_file()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
