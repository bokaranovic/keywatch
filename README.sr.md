# KeyWatch (srpski)

**Uhvati OpenAI i Anthropic API ključeve prije nego procure.**

KeyWatch nalazi izložene API ključeve — OpenAI (`sk-proj-…`, `sk-svcacct-…`,
`sk-admin-…`, stari `sk-…`) i Anthropic (`sk-ant-…`) — u fajlovima, git
historiji, staged izmjenama i tvojim GitHub repoima. Skenira na zahtjev,
prati mape u realnom vremenu i **blokira ključ da nikad ne uđe u commit ni
na push**.

- 🔍 **Skeniranje** — fajlovi, mape i cijela git historija (i davno obrisani ključevi).
- 🛡️ **Git hookovi** — blokada (ili automatsko uklanjanje) na `git commit` i `git push`.
- ⚙️ **GitHub Action** — CI padne ako je ključ u repou.
- 👀 **Watch režim** — alarm u konzoli / na Telegram čim se ključ pojavi na disku.
- 🔢 **Globalna statistika** — koliko je ključeva izloženo na GitHubu (samo brojevi).
- 🔒 **Privatnost po dizajnu** — ključevi se NIKAD ne ispisuju ni čuvaju u cjelini:
  prikaz je maskiran (`sk-proj-AbCdEf…9xYz`), nalazi nose samo SHA-256
  fingerprint. GitHub provjera gleda **samo tvoj nalog** i nikad ne sakuplja
  tuđe ključeve.

## Zahtjevi

Python 3.8+ — bez zavisnosti. Za GitHub provjeru: [`gh` CLI](https://cli.github.com)
ulogovan (`gh auth login`).

## Brzi start

```bash
python keywatch.py selftest            # provjera detekcije (offline) -> 10 OK, 0 FAIL
python keywatch.py scan "C:/Users/Bob/Projekti"      # skeniraj sada
python keywatch.py hook "C:/Users/Bob/Projekti/app"  # zaštita: pre-commit + pre-push
```

## Komande

| Komanda | Šta radi |
|---|---|
| `scan PATH...` | skeniraj fajlove/mape sada |
| `watch PATH...` | prati stalno, alarm na svaki novi ključ |
| `git REPO` | cijela git historija (svi commit-i, sve grane) |
| `gitroot ROOT` | svi `.git` repoi ispod ROOT |
| `staged` | staged izmjene (koristi pre-commit hook) |
| `prepush` | commit-i koji se šalju (koristi pre-push hook) |
| `hook REPO [--redact]` | instaliraj pre-commit + pre-push zaštitu |
| `github [USER]` | provjeri SVOJE repoe (tuđi nalozi se odbijaju) |
| `stats` | globalni brojevi izloženosti na GitHubu |
| `selftest` | provjera da detekcija radi |

Exit kod: `0` = čisto, `1` = nađen ključ (to blokira commit/push u hookovima).

## Zaštita pri commitu i push-u

```bash
python keywatch.py hook "C:/projekat/app"            # blokada
python keywatch.py hook "C:/projekat/app" --redact   # sam ukloni ključ i pusti commit
```

- **pre-commit** — skenira staged izmjene; sa `--redact` zamijeni ključ sa
  `UKLONJENO_KEYWATCH`, ponovo stage-uje i pusti commit; bez njega blokira.
- **pre-push** — skenira commit-e koji se šalju (i postojeću historiju) i
  blokira push ako ima ključ. Ako sken ne može da se izvrši — **blokira**
  (fail-closed), nikad ne propušta naslijepo.

Postojeći hookovi se čuvaju kao `.bak`.

### GitHub push protection (server-side, besplatno na javnim repoima)

*Settings → Code security* → uključi secret scanning + push protection.
GitHub tada sam odbija push sa prepoznatim ključem i obavještava provajdera
(OpenAI i Anthropic učestvuju) koji ključ revokuje.

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
          fetch-depth: 0          # cijela historija (inače je checkout plitak)
      - uses: bokaranovic/keywatch@main
```

## Telegram alarmi

```bash
python keywatch.py watch "C:/projekat" --interval 10
```

Alarm ide i na Telegram ako je bot podešen: `KEYWATCH_TG_BOT_TOKEN` +
`KEYWATCH_TG_CHAT_ID` (ili `TELEGRAM_BOT_TOKEN` / `TELEGRAM_HOME_CHANNEL`).

## Šta prepoznaje

| Tip | Formati |
|---|---|
| OpenAI | `sk-proj-…`, `sk-svcacct-…`, `sk-admin-…`, stari `sk-…` (48 znakova) |
| Anthropic | `sk-ant-api03-…`, `sk-ant-admin01-…`, `sk-ant-oat01-…` |
| .env / config | `OPENAI_API_KEY=…`, `ANTHROPIC_API_KEY: "…"`, i JSON varijante (srednja pouzdanost) |

Placeholderi se ignorišu (`sk-xxxx…`, `sk-ant-your-key-here`, `$OPENAI_API_KEY`,
`<unesi-kljuc>`, primjeri iz dokumentacije). Preskakanje: `keywatch.ignore`
(glob po liniji) ili `--ignore "glob"`.

## Dnevni skan (Task Scheduler)

```bat
schtasks /Create /TN "KeyWatch dnevni skan" /SC DAILY /ST 09:00 /TR "python C:\Users\Bob\tools\keywatch\keywatch.py scan C:\Users\Bob\Projekti"
```

## Preskakanje (allowlist)

Fajl `keywatch.ignore` pored skripte — jedan glob po liniji, `#` = komentar.
Ili `--ignore "glob"` po pozivu.

## GitHub provjera — detalji

- GitHub API koristi stariji code search: `path:*.json` wildcard i zagrade u
  upitu ne rade (422) → koristi se `extension:json`; OR-lanci ne rade →
  jedan upit po terminu.
- Limit 10 upita/min → `--pace` (default 7s); pun run ~6,5 min (6 + 48
  upita); rate limit se sam prepozna (pauza 75s pa nastavi).
- `--quick` = samo osnovni termini (~10 s); `--no-verify` = bez provjere sadržaja.

## Licenca

MIT — vidi [LICENSE](LICENSE).
