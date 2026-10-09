# SSHerlock (aka the threat-intel-tool)
ssherlock-triage: SSH log triage with explained verdicts

> *Somebody tried the root password 6 times. The 7th one worked. Was that a clumsy admin, or the worst night of your quarter?*

That's the question this tool exists to answer.

---

## The scene

Picture an SSH log. Thousands of lines. Most are noise: bots rattling doorknobs, a human fat-fingering a password.

Buried inside is the line that matters:

```
Failed password for root from 200.51.100.7   (x6)
Accepted password for root from 200.51.100.7
```

Six failures, then a way in. That's not a typo. That's a break-in.

I solved a lab like this on HackTheBox (Brutus: one IP hammering root, then a successful login, then a backdoor account). I found it with `grep`, `sort` and `uniq`. It worked, but I did it by hand, once, on one file.

So I built the thing that does it every time.

---

## What it actually does

Feed it an SSH auth log. It then:

1. **Reads the log** and counts failed logins per IP
2. **Spots the plot twist**: did this IP fail repeatedly and *then get in*?
3. **Ignores the noise**: private and reserved addresses are skipped, they can't be real attackers
4. **Ranks the top 5 offenders** (saves your API quota)
5. **Asks VirusTotal and AbuseIPDB** what they know about each one
6. **Gives a verdict, and shows its work**: `CLEAN`, `SUSPICIOUS` or `MALICIOUS`, with the reasons listed

Most IP checkers answer *"is this IP bad?"* for an IP you already have. This one starts from the log and **finds the IPs worth worrying about**.

---

## What it looks like

```
200.51.100.7 -> SUSPICIOUS (score 50)
    - 6 failed logins
    - Login succeeded after failures

69.5.169.170 -> MALICIOUS (score 70)
    - AbuseIPdb score 100
    - VirusTotal: 10 engines flagged

202.0.113.46 -> CLEAN (score 0)
```

No mystery number. Every verdict comes with the evidence behind it, so an analyst can agree or disagree in ten seconds.

---

## Run it yourself

```bash
git clone <this-repo>
cd threat-intel-tool
pip install -r requirements.txt
```

Create a `.env` file (it's gitignored, never commit it):

```
VT_API_KEY=your_virustotal_key
ABUSEIPDB_KEY=your_abuseipdb_key
```

Then pick your mode:

```bash
python cli.py --log test.log      # analyse an SSH log (the main event)
python cli.py --bulk ips.txt      # check every IP found in a text file
python cli.py                     # type IPs by hand, comma separated
```

Run the tests:

```bash
python -m pytest -v
```

The first run is slow on purpose: VirusTotal's free tier allows 4 requests a minute, so the tool paces itself. Run it again and results come from a local SQLite cache (24 hours), so it's instant.

---

## How it decides

Points add up, capped at 100.

| Signal | Points |
|---|---|
| AbuseIPDB confidence score above 75 | +40 |
| AbuseIPDB confidence score above 25 | +20 |
| VirusTotal: 5+ engines say malicious | +30 |
| 5+ failed logins | +20 |
| Successful login *after* 5+ failures | +30 |

**70+** is `MALICIOUS`. **30+** is `SUSPICIOUS`. Anything lower is `CLEAN`.

A success after only one or two failures adds nothing. People mistype passwords. Brute force takes persistence.

---


## Not built yet (honest list)

- Say *"VirusTotal unavailable"* instead of quietly scoring 0 when an API fails
- IPv6 support (the log regex is IPv4 only)
- More log types: nginx, Apache, Windows event logs
- Attempts-per-minute analysis and MITRE ATT&CK tagging (T1110, brute force)
- GreyNoise, to filter out harmless internet scanners
- Shodan enrichment

---

## Under the hood

```
parsers.py   log parsing, IP extraction, brute-force-then-success detection
intel.py     VirusTotal + AbuseIPDB lookups, cache-aware
cache.py     SQLite cache (24h)
scoring.py   points, verdicts, reasons
cli.py       the command line
```

Python, `requests`, `python-dotenv`, `sqlite3`, `pytest`.

---

*Related: my Brutus writeup, where I did all of this by hand with grep. [Read it here](https://aarushi-anand.github.io/posts/brutus/) 🖤*