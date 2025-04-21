# Stealer‑Log Kit 🛠️

A **penetration‑testing utility** that parses leaked stealer‑log archives and turns them into actionable datasets for password‑reuse audits, cookie‑replay demos, and word‑list generation.

> **For authorised engagements only.**  
> Do **not** use on systems or data you do not own or have explicit permission to test.

## Features

* ✂️ **Parse** ZIP / RAR / 7z logs into JSON (passwords, cookies, uncategorised files).  
* 📝 **Word‑list generator** – one‑command unique password list.  
* 📊 **Summary** – quick stats for your report (counts, top domains).  
* 🚪 **Credential‑check PoC** – test passwords against a staging login endpoint.  
* 🔌 Minimal deps, pure‑Python (rarfile / py7zr optional).

## Quick Start

```bash
python -m pip install -r requirements.txt

# Parse stealer logs (limit scope to your org's domains)
python stealer_log_kit.py parse --in ./logs --out ./parsed --domains example.com

# Generate a unique password word list
python stealer_log_kit.py wordlist --parsed ./parsed/passwords.json --out wordlist.txt

# Produce a one‑screen JSON summary
python stealer_log_kit.py summary --parsed ./parsed
```

## Parsed Output Layout

```
parsed/
  passwords.json   -> list of {url, username, password, source}
  cookies.json     -> Netscape cookie dicts
  other_files.json -> non‑parsed artefacts (hash + path)
```

## Credential‑Check Proof‑of‑Concept

The **check** command performs a *minimal* credential‑stuffing simulation against a
staging login endpoint (HTTP POST). Use it **only with explicit client approval**.

```bash
python stealer_log_kit.py check \
  --parsed ./parsed/passwords.json \
  --url https://staging.example.com/login \
  --user-field email --pass-field password --success-code 302
```

## Roadmap

* YARA‑based artefact detection (eg., `aws_secret_access_key` regex).  
* Selenium cookie‑import helper for web apps.  
* Modular export to CSV for Excel‑centric clients.

## Ethical Notice

This tool handles stolen data. Always follow your organisation’s red‑team legal
guidelines and client contracts. Delete or secure artefacts after the engagement.

## License

MIT © 2025 Joyce Johnson
