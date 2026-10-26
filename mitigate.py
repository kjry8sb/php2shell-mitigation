#!/usr/bin/env python3
"""
mitigate.py -- apply the CVE-2026-109618 / CVE-2026-109619 workarounds to a
PHP configuration file.

Supported files (auto-detected):
  - php.ini style            : "memory_limit = 128M"           (';' comments)
  - PHP-FPM pool .conf style : "php_admin_value[memory_limit] = 128M"
                               and "php_value[...] / php_flag[...]" (';' comments)
  - Apache conf style        : "php_admin_value memory_limit 64M" and
                               "php_admin_flag session.upload_progress.enabled on"
                               ('#' comments)

The workarounds (from the official PHP announcement, refs/php.txt):
  1. session.upload_progress.enabled = Off   (defuses the demonstrated
     exploit chain; the setting must be active BEFORE request parsing)
  2. memory_limit = -1                       (removes the OOM trigger)
  3. post_max_size / upload_max_filesize     (size caps; both optional)
  4. fatal_error_backtraces = Off            (PHP 8.5 only, optional)

By default this script is DRY-RUN: it shows exactly what it would change.
Pass --apply-fix to write. It always:
  - writes the new file to <file>.bak-<timestamp> first, then swaps it in
    (the original content is preserved in the backup)
  - comments out any earlier active setting of the same key (never deletes
    lines), then appends the new setting at the end of the file
  - re-reads the file afterwards and re-checks it with the same policy as
    check.py, so the exit code tells you whether the file is now clean

Usage:
  python3 mitigate.py -f /etc/php/8.4/fpm/pool.d/www.conf            # dry run
  python3 mitigate.py -f /etc/php/8.4/fpm/pool.d/www.conf --apply-fix
  python3 mitigate.py -f /etc/php/8.4/apache2/php.ini --apply-fix
  python3 mitigate.py -f /etc/apache2/sites-enabled/x.conf --apply-fix
  python3 mitigate.py -f php.ini --apply-fix --memory-limit 256M     # finite cap
  python3 mitigate.py -f pool.conf --apply-fix --no-post-max         # skip 3

Exit codes: 0 clean, 1 findings remain in the file, 2 usage/IO error.
"""

import argparse
import os
import re
import requests
import sys
import time

from systext import banner, info, success, warning, error

FIXES = [
    ("session.upload_progress.enabled", "Off", True,
     "defuses the demonstrated exploit chain (CVE-2026-109619)"),
    ("memory_limit", "-1", False,
     "removes the out-of-memory trigger (CVE-2026-109618)"),
    ("post_max_size", "8M", False,
     "caps the request body size"),
    ("upload_max_filesize", "2M", False,
     "caps a single uploaded file"),
]

BOOL_KEYS = {"session.upload_progress.enabled", "fatal_error_backtraces"}


def parse_shorthand(v):
    v = (v or "").strip()
    m = re.match(r"^(-?\d+)([KMG]?)$", v, re.IGNORECASE)
    if not m:
        return None
    n = int(m.group(1))
    mult = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}
    return n * mult[m.group(2).lower()]


def truthy(v):
    return str(v).strip().lower() in ("on", "1", "true", "yes")


# ---------------------------------------------------------------- detection

RE_FPM_BRACKET = re.compile(r"^\s*php_(?:admin_)?(?:value|flag)\s*\[")
RE_APACHE_RAW = re.compile(r"^\s*php_(?:admin_)?(?:value|flag)\s+[A-Za-z0-9_.\-]")
RE_APACHE_TAG = re.compile(r"^\s*<(?:VirtualHost|Directory|IfModule|Files)")
RE_FPM_POOL = re.compile(r"^\s*(?:pm\.(?:max_children|start_servers|"
                         r"max_spare_servers)|listen\s*=|chroot\s*=)")


def detect_syntax(text):
    """'fpm' | 'apache' | 'ini'."""
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith((";", "#")):
            continue
        if RE_FPM_BRACKET.match(s) or RE_FPM_POOL.match(s):
            return "fpm"
        if RE_APACHE_RAW.match(s) or RE_APACHE_TAG.match(s):
            return "apache"
    return "ini"


def active_patterns(key, syntax):
    """Regexes matching an ACTIVE assignment of key in this syntax."""
    k = re.escape(key)
    if syntax == "fpm":
        return [re.compile(r"^\s*php_(?:admin_)?(?:value|flag)\s*\[\s*%s\s*\]\s*=" % k)]
    if syntax == "apache":
        # "php_admin_value key value" / "php_flag key on" (no '=')
        return [re.compile(r"^\s*php_(?:admin_)?(?:value|flag)\s+%s(?:\s|$)" % k)]
    return [re.compile(r"^\s*%s\s*=" % k)]


def current_values(text, syntax):
    """Scan active assignments -> {key: (value, line_index)}.
    First (topmost) active assignment wins, like the effective value order
    for FPM bracket keys and Apache per-dir merging (server level first)."""
    found = {}
    lines = text.splitlines()
    for i, line in enumerate(lines):
        s = line.strip()
        if not s or s.startswith((";", "#")):
            continue
        if syntax == "fpm":
            m = re.match(r"^php_(?:admin_)?(?:value|flag)\s*"
                         r"\[\s*([^]]+?)\s*\]\s*=\s*(.+)$", s)
            if m:
                found.setdefault(m.group(1), (m.group(2).strip().strip('"\''), i))
        elif syntax == "apache":
            m = re.match(r"^php_(?:admin_)?(?:value|flag)\s+"
                         r"([A-Za-z0-9_.\-]+)\s+(.+)$", s)
            if m:
                val = m.group(2).strip().split()
                found.setdefault(m.group(1), (val[0] if val else "", i))
        else:
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*=\s*(.*)$", s)
            if m:
                found.setdefault(m.group(1), (m.group(2).strip().strip('"\''), i))
    return found


def check_file(text, syntax, opts):
    """check.py policy over a file's settings. Returns (findings, notes)."""
    findings, notes = [], []
    vals = current_values(text, syntax)

    up = vals.get("session.upload_progress.enabled", (None,))[0]
    if up is not None and truthy(up):
        findings.append(("VULN", "UPLOAD_PROGRESS_ON",
                         "session.upload_progress.enabled = On"))
    elif up is not None:
        notes.append("session.upload_progress.enabled = Off (good)")

    ml = vals.get("memory_limit", (None,))[0]
    if ml is not None and parse_shorthand(ml) not in (None, -1):
        findings.append(("WARN", "MEMORY_LIMIT_FINITE",
                         "memory_limit = %s (finite)" % ml))
    elif ml is not None:
        notes.append("memory_limit = %s (unlimited; OOM trigger removed)" % ml)

    if opts.fatal_backtraces:
        fb = vals.get("fatal_error_backtraces", (None,))[0]
        if fb is not None and truthy(fb):
            findings.append(("WARN", "FATAL_BACKTRACES_ON",
                             "fatal_error_backtraces = On (PHP 8.5 only)"))

    de = vals.get("display_errors", (None,))[0]
    if de is not None and truthy(de):
        findings.append(("WARN", "DISPLAY_ERRORS_ON",
                         "display_errors = On (leak channel)"))
    return findings, notes


def append_line(key, value, syntax):
    if syntax == "fpm":
        kw = "php_admin_flag" if key in BOOL_KEYS else "php_admin_value"
        return "%s[%s] = %s" % (kw, key, value)
    if syntax == "apache":
        kw = "php_admin_flag" if key in BOOL_KEYS else "php_admin_value"
        return "%s %s %s" % (kw, key, str(value).lower())
    return "%s = %s" % (key, value)


COMMENT = {"ini": ";", "fpm": ";", "apache": "#"}


# ---------------------------------------------------------------- apply

def apply_fixes(path, opts):
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        text = f.read()
    syntax = detect_syntax(text)
    banner("PHP MITIGATE", subtitle=path)
    info(f"file       : {path}")
    info(f"syntax     : {syntax}")

    fixes = [(k, v) for (k, v, _b, _w) in FIXES]
    if opts.memory_limit is not None:
        fixes = [(k, opts.memory_limit if k == "memory_limit" else v)
                 for (k, v) in fixes]
    if opts.no_post_max:
        fixes = [(k, v) for (k, v) in fixes if k != "post_max_size"]
    if opts.no_upload_max:
        fixes = [(k, v) for (k, v) in fixes if k != "upload_max_filesize"]
    if opts.fatal_backtraces:
        fixes.append(("fatal_error_backtraces", "Off"))

    lines = text.splitlines()
    cmt = COMMENT[syntax]
    changed = 0
    for (key, value) in fixes:
        pats = active_patterns(key, syntax)
        hit = [i for i, ln in enumerate(lines)
               if any(p.match(ln) for p in pats)]
        cur = current_values("\n".join(lines), syntax).get(key)
        already = cur and (
            cur[0].strip().lower() == value.lower() or
            (key == "memory_limit" and
             parse_shorthand(cur[0]) == parse_shorthand(value)))
        if already and not opts.force:
            success(f"{key} already {cur[0]}")
            continue
        for i in hit:  # comment out earlier active assignments
            lines[i] = "%s disabled by mitigate.py (CVE-2026-109618/109619) --> %s" \
                       % (cmt, lines[i])
            changed += 1
        lines.append(append_line(key, value, syntax))
        changed += 1
        info(f"{key} = {value}")

    if not changed:
        success("nothing to change (all fixes already in place)")
        return 0

    if opts.apply_fix:
        newtext = "\n".join(lines) + "\n"
        backup = "%s.bak-%s" % (path, time.strftime("%Y%m%d-%H%M%S"))
        with open(backup, "w", encoding="utf-8", errors="surrogateescape",
                  newline="\n") as f:
            f.write(text)  # original content preserved in the backup
        tmp = path + ".mitigate-tmp"
        with open(tmp, "w", encoding="utf-8", errors="surrogateescape",
                  newline="\n") as f:
            f.write(newtext)
        os.replace(tmp, path)
        success(f"wrote {path} ({changed} line edits; original saved as {backup})")
    else:
        warning(f"DRY RUN: {changed} line edits would be written to {path} (pass --apply-fix to write)")

    # ---- post-verify ----
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        after, notes = check_file(f.read(), syntax, opts)
    info("post-verify of the FILE (run check.py against the PHP binary for the version check too):")
    if after:
        for (sev, code, msg) in after:
            if sev == "VULN":
                error(f"{code}: {msg}")
            elif sev == "WARN":
                warning(f"{code}: {msg}")
            else:
                warning(f"{code}: {msg}")
    else:
        success("none -- workaround settings present in the file")
    for n in notes:
        success(n)
    info("REMEMBER: restart the PHP workers for changes to take effect:")
    info("  systemctl restart php-fpm / apachectl restart (running workers keep the old config AND the stale state)")
    return 1 if after else 0


def main():
    ap = argparse.ArgumentParser(
        description="Apply CVE-2026-109618/109619 ini workarounds "
                    "(dry-run by default)")
    ap.add_argument("-f", "--file", required=True,
                    help="php.ini, FPM pool .conf, or Apache .conf to edit")
    ap.add_argument("--apply-fix", dest="apply_fix", action="store_true",
                    help="actually write the file (default: dry run)")
    ap.add_argument("--memory-limit", default=None,
                    help="override the memory_limit value to set "
                         "(default -1 = unlimited)")
    ap.add_argument("--no-post-max", action="store_true",
                    help="skip the post_max_size fix")
    ap.add_argument("--no-upload-max", action="store_true",
                    help="skip the upload_max_filesize fix")
    ap.add_argument("--fatal-backtraces", action="store_true",
                    help="also set fatal_error_backtraces = Off (8.5 only)")
    ap.add_argument("--force", action="store_true",
                    help="re-apply even if the value is already correct")
    args = ap.parse_args()

    if not os.path.isfile(args.file):
        error(f"no such file: {args.file}")
        return 2
    return apply_fixes(args.file, args)


if __name__ == "__main__":
    sys.exit(main())
