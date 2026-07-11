# Web Health Scanner

A command-line tool that checks a website's health, security posture, and SSL certificate status — and turns the results into a single readable report with an overall score.

I built this to learn how real web infrastructure works under the hood: HTTP status codes, TLS handshakes, security headers, redirect chains, and how to turn raw network data into something a non-technical person could actually read.
___
Streamlit Link:
https://web-health-scanner-99.streamlit.app/
___

## What it checks

- **Uptime & response time** — is the site reachable, what status code does it return, how fast does it respond
- **Security headers** — checks for 5 headers that protect against common attacks (clickjacking, MIME-sniffing, XSS, downgrade attacks)
- **SSL certificate** — is the certificate valid, who issued it, how many days until it expires
- **Redirects** — does the site force HTTPS, how many redirect hops does it take
- **Overall score** — combines all of the above into a single score out of 10
- **Input validation** — handles empty input, malformed URLs, missing protocols, and unreachable hosts without crashing

## Why these checks matter

- Missing security headers is one of the most common findings in real security audits — sites can be functionally fine and still leave users exposed
- An expired SSL certificate silently breaks a site for every visitor with no warning
- Sites that don't force HTTPS allow traffic to be intercepted in plain text

## How to run it

```bash
pip install requests
py checker.py https://example.com
```

If you don't include a protocol, the tool adds `https://` automatically:

```bash
py checker.py example.com
```

Or run it interactively:

```bash
py checker.py
enter the url to test: example.com
```

## Sample output

```
=== Report for https://google.com ===
Reachable: True | Status: 200
Response time: 1068.96 ms

Security Headers:
  Strict-Transport-Security: Missing
  Content-Security-Policy: Missing
  X-Frame-Options: Present
  X-Content-Type-Options: Missing
  Referrer-Policy: Missing

SSL valid: True | Expires in: 64 days
Redirect count: 1 | Forces HTTPS: True

Overall Score: 6/10
Saved to report.json
```

Every run also saves a full JSON report (`report.json`) for further processing or record-keeping.

## Project structure

```
web-health-scanner/
├── checker.py       # main tool: health, headers, redirects, scoring, CLI
├── ssl_checker.py   # SSL certificate inspection
└── report.json      # generated after each run
```

## What I learned building this

- How HTTP works below the surface — status codes, headers, timing
- How TLS certificates are structured and how to inspect them with Python's `ssl` and `socket` modules directly (not just through `requests`)
- Why security headers exist and what each one actually protects against
- How to separate "collecting data" from "judging data" — the checker functions return raw facts, and a separate scoring function decides what's good or bad
- Defensive coding: validating input before trusting it, catching specific exceptions instead of one generic `except`

## Possible next steps

- Streamlit dashboard for a visual, non-CLI version
- Batch mode to scan a list of URLs from a file
- Historical tracking to compare scores over time

## Tech used

Python · `requests` · `socket` · `ssl` · `json`
