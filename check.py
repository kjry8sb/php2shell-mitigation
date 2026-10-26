#!/usr/bin/env python3
"""
check.py -- CVE-2026-109618 / CVE-2026-109619 local PHP vulnerability checker.

Scans a PHP installation and reports whether it is vulnerable to the two
"session.upload_progress" out-of-memory / stale-state RCE bugs, and whether
the recommended workaround settings are in place. READ-ONLY: never modifies
anything, never talks to the network.

What it checks (all locally, via the PHP binary itself):
  1. Version        -- PHP 5.4.0 .. 8.5.11 is vulnerable
                      (fixed: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12)
  2. memory_limit   -- a finite value lets an attacker force the
                      out-of-memory failure during request startup
  3. session.upload_progress.enabled -- must be Off to defuse the
                      demonstrated exploit chain
  4. display_errors -- On leaks heap addresses in the exploit's error
                      output (hardening, not the vulnerability itself)
  5. session.save_path -- /tmp-style world-writable paths are what the
                      demonstrated chain uses (informational)

Exit code 0 = no finding (or only notes), 1 = at least one finding,
2 = could not run the PHP binary at all.

Usage:
  python3 check.py                       # auto-find php in PATH
  python3 check.py -p /usr/bin/php       # explicit binary
  python3 check.py -p php -c /etc/php.ini  # check a specific php.ini
  python3 check.py --json                # machine-readable output
"""

import argparse
import json
import re
import requests
import shutil
import subprocess
import sys

from systext import banner, info, success, warning, error

# Fixed versions per branch (from the official PHP announcement, refs/php.txt).
FIXED = {
    8: {5: (12,), 2: (35,), 3: (36,), 4: (27,)},  # 8.5.12, 8.2.35, 8.3.36, 8.4.27
}

VULN_RANGE = ((5, 4, 0), (8, 5, 11))  # inclusive


def version_tuple(vstr):
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", vstr or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def is_vulnerable(ver):
    """True if the parsed version is inside the vulnerable range."""
    if ver is None:
        return None
    if not (VULN_RANGE[0] <= ver <= VULN_RANGE[1]):
        return False
    # Inside the range but on a fixed branch release?
    branch = FIXED.get(ver[0], {})
    fixes = branch.get(ver[1], ())
    if fixes and ver[2] >= min(fixes):
        return False
    return True


def truthy(v):
    return str(v).strip().lower() in ("on", "1", "true", "yes")


class PhpRunError(Exception):
    pass


def run_php(php, ini, args=()):
    cmd = [php]
    if ini:
        cmd += ["-c", ini]
    cmd += list(args)
    # A nonexistent/old PHP may print to stderr; capture both.
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        raise PhpRunError("could not execute '%s': %s" % (php, e))


def parse_shorthand(v):
    """'128M' -> 134217728, '256K' -> 262144, '-1' -> -1."""
    v = (v or "").strip()
    m = re.match(r"^(-?\d+)([KMG]?)$", v, re.IGNORECASE)
    if not m:
        return None
    n = int(m.group(1))
    mult = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}
    return n * mult[m.group(2).lower()]


def main():
    ap = argparse.ArgumentParser(description="Local PHP CVE-2026-109618/109619 checker")
    ap.add_argument("-p", "--php", default=None,
                    help="path to the PHP binary (default: first 'php' in PATH)")
    ap.add_argument("-c", "--ini", default=None,
                    help="check this php.ini instead of the default one")
    ap.add_argument("--json", action="store_true",
                    help="emit JSON instead of human output")
    args = ap.parse_args()

    php = args.php or shutil.which("php")
    if not php:
        error("no 'php' binary found in PATH; pass one with -p")
        return 2

    findings = []   # (severity, code, message)
    settings = {}   # raw ini values
    notes = []

    # ---- 1. version ----
    try:
        r = run_php(php, args.ini, ["-n", "-v"])
    except PhpRunError as e:
        error(str(e))
        return 2
    ver_str = ""
    if r.returncode == 0:
        m = re.search(r"^PHP (\S+)", r.stdout, re.MULTILINE)
        if m:
            ver_str = m.group(1)
    ver = version_tuple(ver_str)

    if ver is None:
        findings.append(("ERROR", "VERSION_UNKNOWN",
                         "could not parse the PHP version from '%s -v'" % php))
    else:
        vuln = is_vulnerable(ver)
        if vuln is True:
            findings.append(("VULN", "VERSION_VULNERABLE",
                             "PHP %s is VULNERABLE to CVE-2026-109618 and "
                             "CVE-2026-109619 (fixed in 8.2.35/8.3.36/8.4.27/"
                             "8.5.12)" % ver_str))
        elif vuln is False:
            notes.append("PHP %s is not in the vulnerable range "
                         "(5.4.0 - 8.5.11)" % ver_str)
        settings["version"] = ver_str

    # ---- effective settings under the (optional) ini ----
    r = run_php(php, args.ini, ["-i"])
    out = r.stdout + r.stderr
    settings_raw = {}
    if r.returncode in (0,):
        # php -i prints:  key => master => local   (local == effective)
        for key in ("memory_limit", "session.upload_progress.enabled",
                    "display_errors", "session.save_path",
                    "session.use_strict_mode", "post_max_size"):
            m = re.search(r"^%s => (.+?)(?: => .*)?$" % re.escape(key),
                          out, re.MULTILINE)
            if m:
                settings_raw[key] = m.group(1).strip()
    if not settings_raw:
        # fall back to -r ini_get (some builds route -i oddly in CGI mode)
        r2 = run_php(php, args.ini, [
            "-r",
            "echo ini_get('memory_limit'),'|',"
            "ini_get('session.upload_progress.enabled'),'|',"
            "ini_get('display_errors'),'|',"
            "ini_get('session.save_path');"
        ])
        if r2.returncode == 0 and "|" in r2.stdout:
            ml, up, de, sp = (r2.stdout.split("|") + ["", "", "", ""])[:4]
            settings_raw = {
                "memory_limit": ml,
                "session.upload_progress.enabled": up,
                "display_errors": de,
                "session.save_path": sp,
            }

    # ---- 2. memory_limit ----
    ml = settings_raw.get("memory_limit")
    settings["memory_limit"] = ml
    if ml is not None:
        mlb = parse_shorthand(ml)
        if mlb is not None and mlb == -1:
            notes.append("memory_limit = -1 (unlimited): the OOM trigger of "
                         "CVE-2026-109618 is disarmed, but the vulnerability "
                         "itself is still present")
        elif mlb is not None:
            findings.append(("WARN", "MEMORY_LIMIT_FINITE",
                             "memory_limit = %s -- an attacker can force the "
                             "CVE-2026-109618 out-of-memory condition by "
                             "sending a request body slightly larger than "
                             "this" % ml))
        else:
            notes.append("memory_limit '%s' could not be parsed" % ml)

    # ---- 3. session.upload_progress.enabled ----
    up = settings_raw.get("session.upload_progress.enabled")
    settings["session.upload_progress.enabled"] = up
    if up is not None:
        if truthy(up):
            findings.append(("VULN", "UPLOAD_PROGRESS_ON",
                             "session.upload_progress.enabled = On -- the "
                             "demonstrated OOMBA exploit chain needs this; "
                             "turn it Off if the application does not rely "
                             "on it (official workaround for "
                             "CVE-2026-109619)"))
        else:
            notes.append("session.upload_progress.enabled = Off (good; the "
                         "demonstrated chain is defused)")

    # ---- 4. display_errors ----
    de = settings_raw.get("display_errors")
    settings["display_errors"] = de
    if de is not None and truthy(de):
        findings.append(("WARN", "DISPLAY_ERRORS_ON",
                         "display_errors = On -- the heap-address leak in the "
                         "exploit rides on displayed error output; should be "
                         "Off in production"))

    # ---- 5. session.save_path ----
    pr = settings_raw.get("session.save_path")
    settings["session.save_path"] = pr
    if pr and pr not in ("no value", ""):
        norm = pr.replace("\\", "/")
        if norm.rstrip("/").endswith("/tmp") or "/tmp/" in norm:
            notes.append("session.save_path = %s -- shared /tmp-style path "
                         "used by the demonstrated chain (informational)" % pr)

    # ---- output ----
    if args.json:
        print(json.dumps({
            "php": php,
            "settings": settings,
            "findings": [{"severity": s, "code": c, "message": m}
                          for (s, c, m) in findings],
            "notes": notes,
        }, indent=2))
    else:
        banner("PHP CHECK", subtitle=f"PHP {settings.get('version', '?')}")
        info(f"PHP binary : {php}")
        if args.ini:
            info(f"php.ini    : {args.ini}")

        if findings:
            for (sev, code, msg) in findings:
                if sev == "VULN":
                    error(f"{code}: {msg}")
                elif sev == "WARN":
                    warning(f"{code}: {msg}")
                elif sev == "ERROR":
                    error(f"{code}: {msg}")
                else:
                    warning(f"{code}: {msg}")
        for n in notes:
            success(n)
        if not findings and not notes:
            success("no findings")

        if any(f[0] == "VULN" for f in findings):
            error("RESULT: VULNERABLE -- upgrade PHP and apply the workarounds in MITIGATION.md")
        elif findings:
            warning("RESULT: ATTENTION -- hardening recommended (see MITIGATION.md sections 3 and 6)")
        else:
            success("RESULT: OK (version out of range; check the settings notes above)")

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
