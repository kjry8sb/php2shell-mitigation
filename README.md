# MITIGATION — detect and work around CVE-2026-109618 / CVE-2026-109619

Files in this folder:

- `MITIGATION.md` — the complete plain-English manual: what the two CVEs
  are, upgrade routes, temporary defenses, signatures for spotting attacks,
  apply/verify/cleanup scripts, and cautions
- `check.py` — a non-destructive scan: is this PHP build affected, and have
  the workaround settings been put in place?
- `mitigate.py` — injects the workarounds into php.ini / FPM pool / Apache
  conf (dry-run by default; pass `--apply-fix` to write — a backup and
  post-apply verification are included).

Both are unit-tested (18/18) and were exercised against real PHP 5.5.38,
7.4.33, 8.4.26 and 8.5.4 binaries.

## Quick start

```bash
# 1. Is this PHP vulnerable? (read-only)
python -I mitigation/check.py -p /path/to/php          # or no -p to use PATH
python -I mitigation/check.py -p php --json            # machine-readable

# 2. Apply the workarounds to a config file (dry-run first — ALWAYS look)
python -I mitigation/mitigate.py -f /etc/php/8.4/fpm/pool.d/www.conf
python -I mitigation/mitigate.py -f /etc/php/8.4/apache2/php.ini --apply-fix

# 3. Re-check (note: the version finding stays until you upgrade PHP)
python -I mitigation/check.py -p php -c /etc/php/8.4/apache2/php.ini

# 4. Restart the workers — required
systemctl restart php8.4-fpm   # or: apachectl restart
```

## What the scripts change

| setting | value | why |
|---|---|---|
| `session.upload_progress.enabled` | Off | breaks the demonstrated exploit chain (the official workaround) |
| `memory_limit` | -1 | takes away the out-of-memory trigger (the official workaround) |
| `post_max_size` | 8M | bounds how large a request body may be |
| `upload_max_filesize` | 2M | bounds how large any single uploaded file may be |
| `fatal_error_backtraces` | Off | PHP 8.5 only; opt in with `--fatal-backtraces` |

mitigate.py never removes lines: an earlier active assignment is commented
out behind a marker, the replacement value is appended, and the untouched
original is preserved as `<file>.bak-<timestamp>`. Running it repeatedly is
safe (idempotent).

## Exit codes (both scripts)

- 0 — all clear / nothing needs doing
- 1 — findings remain (check) / the file still shows findings after apply (mitigate)
- 2 — the binary could not be executed / the file does not exist

## Verification performed (2026-10-22)

- check.py against live binaries: 8.4.26, 8.5.4, 7.4.33, 5.5.38 (every one
  reported VULN under a stock-style ini), JSON mode, and error paths (exit 2).
- Version-classifier unit tests: 18/18 (point releases on the fixed branches
  and everything newer report as not vulnerable, e.g. 8.4.28).
- mitigate.py across all three syntax families (php.ini, FPM pool, Apache
  vhost conf): correct disables, correct append forms, idempotent repeated
  runs; the real PHP binary loaded the mitigated php.ini and `ini_get`
  confirmed every setting was in effect.
- Full roundtrip: check (VULN) -> mitigate --apply-fix -> check (only the
  version finding remains, and only an upgrade clears that one).
