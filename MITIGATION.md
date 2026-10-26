# MITIGATION.md — Defending PHP servers from CVE-2026-109618 and CVE-2026-109619

A plain-English manual on finding and blocking two critical remote code
execution flaws in PHP's file-upload progress tracking. Everything below
rests on this project's own hands-on reproduction (the full evidence trail
lives in `POC/oomba/` and `KNOWLEDGE.md`) together with the official PHP
security announcement (`refs/php.txt`).

Terms used in this document, defined once up front:
- **CVE** — a public catalog number assigned to a security bug ("Common
  Vulnerabilities and Exposures").
- **RCE** — remote code execution: an attacker gets to run commands of
  their choosing on your server, with no authentication required.
- **mod_php** — the PHP interpreter built straight into Apache as a module.
- **PHP-FPM** — the "FastCGI Process Manager", a standalone PHP service
  that Apache or Nginx typically forward requests to.
- **worker process** — one of the long-running server processes that
  serves requests one after another.

---

## 1. The two vulnerabilities, in plain terms

Both flaws sit inside PHP itself — not in WordPress, Laravel, or whatever
application you host. They were patched on 21 October 2026.

### CVE-2026-109618 — "out-of-memory corruption"

When a request demands more memory than `memory_limit` permits, PHP has
historically bailed out through an abrupt jump (a `longjmp`) rather than a
tidy shutdown. If that jump happens while PHP is still *assembling* the
request — for instance while a large file upload is still being read in —
the half-built internal data is simply left sitting in memory. Apache's
built-in PHP module (mod_php) then performs its usual end-of-request
cleanup **even though startup never completed**, and that cleanup treats
the invalid data as legitimate. An attacker who first arranges the right
memory layout achieves remote code execution before a single line of
application code runs.

### CVE-2026-109619 — "stale state across requests"

PHP holds certain request data in memory that outlives the request itself
(inside the worker process). When a request dies from a fatal error or
from memory exhaustion, that leftover data can end up pointing at memory
that was already freed — a stale pointer. The **next request picked up by
the same worker process** consumes the stale data before ordinary
initialization resets it. One confirmed route runs through the
`session.upload_progress` feature, which records upload progress
information into the session while PHP is still parsing the incoming
request.

### Affected and fixed versions

| Status | Versions |
|---|---|
| Vulnerable | PHP 5.4.0 through 8.5.11 (fourteen years of releases) |
| Fixed | **8.2.35, 8.3.36, 8.4.27, 8.5.12** |
| Older lines | PHP 7.4 / 8.0 / 8.1: source-code backports are available from the PHP team; these branches no longer receive routine updates |

The worst exposure is Apache with mod_php — the exploit chain we
demonstrated works from a standing start, against any PHP endpoint, before
any application code executes. PHP-FPM is affected too: in our lab, the
same memory-exhaustion trigger made the FPM child process terminate (log
line: `child ... exited with code 70`) instead of running the attacker's
code, but the official announcement names further variants that do reach
PHP-FPM.

---

## 2. The complete fix: upgrade

Nothing else in this document constitutes a complete fix — upgrading is
the only one.

```bash
# Debian/Ubuntu example:
apt update && apt install php8.4 php8.4-fpm   # or your distribution's packages

# Docker: pin a fixed tag — do not use floating tags like php:8.4-apache:
FROM php:8.4.27-apache
```

Once upgraded, restart the PHP workers (every Apache child, every FPM
pool), because part of the bug lives in process memory that a config
reload never touches.

---

## 3. Workarounds if upgrading isn't possible today

### 3.1 Remove the memory-exhaustion trigger (CVE-2026-109618)

Make the memory limit unlimited so the attacker cannot force the
controlled failure point — and place it somewhere application code cannot
override:

```ini
; PHP-FPM pool file (e.g. /etc/php/8.4/fpm/pool.d/www.conf):
php_admin_value[memory_limit] = -1
```

```apache
# Apache with mod_php, inside a <VirtualHost>:
php_admin_value memory_limit -1
```

Then confirm that no per-directory or application-level setting
reintroduces a finite limit (search your deployment for
`ini_set('memory_limit', ...)`).

Bound the request body size so a single request cannot carry huge
payloads (8 MB when the application handles no file uploads, 32 MB when
it does), and keep the per-file limit below it:

```ini
post_max_size = 8M
upload_max_filesize = 2M
```

These caps must also cover requests sent **without** a `Content-Length`
header (chunked transfers). Enforce a decoded-body-size limit at the web
server or reverse proxy too — including limits on the number of form
fields, multipart parts, per-part headers, and nesting depth.

Use a container or cgroup memory cap as an availability backstop.
**Never use `RLIMIT_AS` or `RLIMIT_DATA`** — an allocation that fails
because of those limits lands precisely on the vulnerable code path.

### 3.2 Turn off upload progress tracking (CVE-2026-109619)

```ini
; php.ini, FPM pool config, or Apache config — anywhere that applies
; BEFORE request parsing starts:
session.upload_progress.enabled = Off
```

```bash
systemctl restart php8.4-fpm      # PHP-FPM
apachectl restart                 # Apache with mod_php
```

**Where you set it matters.** It takes effect in `php.ini`, in the FPM
pool config, or in the Apache server configuration. It does **not** take
effect via `ini_set()` in application code, via FPM `.user.ini` files, or
via any setting merged too late — the value must already be active by the
time PHP begins parsing the incoming request.

### 3.3 PHP 8.5 only: one extra switch

```ini
fatal_error_backtraces = Off
```

This shuts down the "fatal error backtrace" variant of the stale-state
path. Restart the workers afterwards.

### 3.4 Remaining official advice

- Strip out invalid or deprecated PHP settings that get applied per
  request and emit warning messages before initialization — those
  warnings are part of the attack's setup.
- Repair attacker-reachable fatal errors and execution timeouts,
  including failures inside callbacks and in upload/import processing
  and cleanup.

### 3.5 Checklist of settings the demonstrated exploit depends on

None of these are required by the advisory, but the working exploit we
tested (`POC/oomba/`) relies on every one of them — eliminating any
single item breaks the demonstrated chain:

```bash
php -i | grep -E 'display_errors|session.use_strict_mode|session.save_path|max_input_vars'
```

| Setting | Why the exploit needs it | Hardening value |
|---|---|---|
| `display_errors` | On — the heap-address leak travels on error output | Off in production (shuts the leak channel; does not fix the bug) |
| `session.use_strict_mode` | Off — lets the attacker choose the session ID and file name | On |
| `max_input_vars` | 1000 (the default; the attack deliberately straddles this boundary) | Keep the default; raise an alert on ~1000-field POSTs |
| `session.save_path` | A predictable, shared path such as `/tmp` | Restricted permissions; watch the contents |
| Apache multi-processing module | prefork with a single worker makes the attack deterministic | Not a security setting, but be aware that multi-worker setups raise the bar |

---

## 4. How to detect attacks

### 4.1 Log signatures (every one observed live in our lab)

```bash
# Apache with mod_php: worker crash cycles — each FAILED exploit attempt
# crashes one worker:
grep -E "exit signal Segmentation fault|exit signal Abort" /var/log/apache2/error.log
#   [core:notice] AH00051: child pid 1234 exit signal Segmentation fault (11)

# PHP-FPM: the out-of-memory child exit:
grep "exited with code 70" /var/log/php8.4-fpm.log

# The out-of-memory trigger itself, during request startup:
grep "Allowed memory size of .* exhausted .* in Unknown on line 0"

# Stale-state consumer (serializer handler mismatch variant):
grep "Failed to decode session object. Session has been destroyed"
```

A burst of segmentation faults paired with "Allowed memory size …
exhausted" lines is a strong indicator that someone is running the
out-of-memory chain.

### 4.2 Network-side indicators (what the attack traffic looks like)

The entire attack is made of ordinary HTTP multipart POSTs, so
byte-signature rules will not catch it — the *shapes* are what matter:

- A POST form field literally named `PHPSESSID`. Normal browsers only
  ever send session identifiers in the `Cookie` header, never as a form
  field.
- A form field named `PHP_SESSION_UPLOAD_PROGRESS`.
- Roughly 800–1000+ extra small form fields packed into one POST
  (memory-layout grooming; the default `max_input_vars` boundary of 1000
  is approached on purpose).
- One gigantic form field about the size of `memory_limit` — a blob of
  repeated bytes at 8, 12, or 32 MB (the out-of-memory trigger).
- Multipart file names (in the `Content-Disposition` header) containing
  PHP code (`<?php ... ?>`) or a shell breakout pattern: `x";` followed
  by semicolon-separated shell commands ending in `#`.
- Uploads abandoned mid-transfer (the connection closes before the body
  completes) — used to leave a poisoned session file behind.
- **The strongest response-side tell**: a `Set-Cookie: PHPSESSID=...`
  header running to thousands of bytes. A normal value is 32–48
  characters; the memory leak produces roughly 4096 bytes. Alert on any
  PHPSESSID cookie value above 256 bytes.

The attack executes before any application code runs, so rules that
inspect only particular endpoints will miss it — apply them across every
PHP endpoint. The researched `php2shell-poc-main` bundle ships ready-made
rules in its `detection/` folder: 13 Suricata/Snort rules
(`php2shell.rules`), 5 Sigma rules (`php2shell.yaml`) covering web logs,
process creation and file events, a ModSecurity configuration, and a Lua
script.

### 4.3 On the PHP server itself

```bash
# Session files containing PHP code or shell payloads (poisoning):
grep -l '<?php' /var/lib/php/sessions/sess_* /tmp/sess_* 2>/dev/null

# Shell-breakout pattern inside session files:
grep -l 'x";.*#'  /var/lib/php/sessions/sess_* /tmp/sess_* 2>/dev/null

# Single-character session file names (the exploit deliberately uses tiny
# IDs like sess_a / sess_b):
ls -la /tmp/sess_? /var/lib/php/sessions/sess_? 2>/dev/null
```

Treat any `sess_*` file holding `<?php` or the `x";...;#` shell pattern
as a stashed command payload — an indicator of compromise.

### 4.4 One-shot detection script

```bash
#!/bin/sh
# detect-php2shell.sh — scan logs and session files for attack traces.
APACHE_LOG=${APACHE_LOG:-/var/log/apache2/error.log}
FPM_LOG=${FPM_LOG:-/var/log/php8.4-fpm.log}
SESS_DIRS="${SESS_DIRS:-/var/lib/php/sessions /tmp}"

echo "== worker crashes (mod_php) =="
grep -cE "exit signal Segmentation fault|exit signal Abort" "$APACHE_LOG" 2>/dev/null
echo "== FPM out-of-memory exits =="
grep -c "exited with code 70" "$FPM_LOG" 2>/dev/null
echo "== request-startup memory exhaustion =="
grep -c "Allowed memory size of .* exhausted .* in Unknown on line 0" \
  "$APACHE_LOG" "$FPM_LOG" 2>/dev/null
echo "== stale-session decode failures =="
grep -c "Failed to decode session object" "$APACHE_LOG" 2>/dev/null
echo "== poisoned session files =="
grep -l -E '<\?php|x";.*#' $SESS_DIRS/sess_* 2>/dev/null
echo "== single-character session IDs =="
ls $SESS_DIRS/sess_? 2>/dev/null
```

---

## 5. Apply-and-verify scripts

### 5.1 Apply the emergency workarounds (run as root; check the paths first)

```bash
#!/bin/sh
# oomba-mitigate.sh — apply the official workarounds and restart workers.
set -e
INI=${INI:-/etc/php/8.4/fpm/pool.d/www.conf}   # adjust to your install

set_kv() {  # idempotent: update the line if present, append otherwise
  key=$1; val=$2
  grep -q "^\s*${key}" "$INI" \
    && sed -i "s|^\s*${key}.*|${key} = ${val}|" "$INI" \
    || echo "${key} = ${val}" >> "$INI"
}

set_kv 'php_admin_flag[session.upload_progress.enabled]' 'off'
set_kv 'php_admin_value[memory_limit]' '-1'
set_kv 'php_admin_value[post_max_size]' '8M'
set_kv 'php_admin_value[upload_max_filesize]' '2M'

systemctl restart php8.4-fpm
echo "[+] applied to $INI and workers restarted"
```

The mod_php equivalent for Apache, inside each `<VirtualHost>`:

```apache
<IfModule mod_php.c>
    php_admin_flag session.upload_progress.enabled off
    php_admin_value memory_limit -1
    php_admin_value post_max_size 8M
    php_admin_value upload_max_filesize 2M
</IfModule>
```

### 5.2 Confirm the settings are live

```bash
# 1) the files contain what you expect:
grep -E 'upload_progress|memory_limit|post_max_size' \
  /etc/php/8.4/fpm/pool.d/www.conf

# 2) the effective runtime values (FPM pools apply php_admin_* per pool,
#    so check through the web server with a temporary page):
cat > /var/www/html/ini-check.php <<'EOF'
<?php
header('Content-Type: text/plain');
foreach (['session.upload_progress.enabled', 'memory_limit',
          'post_max_size', 'upload_max_filesize'] as $k) {
    echo $k, ' = ', ini_get($k) ?: '(empty/off)', "\n";
}
EOF
curl -s http://127.0.0.1/ini-check.php
rm /var/www/html/ini-check.php   # remove immediately after checking
```

### 5.3 Cleanup if you suspect a compromise

```bash
# 1) stop the service so nothing re-reads the session files:
systemctl stop php8.4-fpm

# 2) quarantine poisoned session files (do NOT run anything from them):
mkdir -p /root/sess_quarantine
grep -l -E '<\?php|x";.*#' /var/lib/php/sessions/sess_* /tmp/sess_* 2>/dev/null \
  | xargs -r mv -t /root/sess_quarantine

# 3) all existing sessions are now untrusted — force re-login app-side.
# 4) restart with the mitigations from 5.1 in place, then audit:
#    - files in the webroot modified around the incident time,
#    - the web user's shell history and cron entries,
#    - unexpected outbound connections.
```

---

## 6. Warnings — read these before trusting the workarounds

1. **These are partial mitigations only.** Per the official announcement,
   nothing short of an update fully resolves the issue. Even with
   `memory_limit = -1`, an allocation failure underneath can still reach
   the vulnerable path.
2. **Placement matters.** `ini_set()` and `.user.ini` take effect too
   late. The settings must already be active before request parsing
   begins: php.ini, the FPM pool configuration, or the Apache server
   configuration.
3. **Suppressing error output is not a repair.** Switching `display_errors`
   off (or lowering `error_reporting`) fixes nothing — the vulnerabilities
   remain and you lose log signal. It does close the information-leak
   channel the demonstrated exploit relies on, which is why it still
   appears in the checklist.
4. **Restart every worker** after changing settings. The stale-state bug
   is, by definition, state that survives inside worker processes; a
   running worker keeps holding both its old configuration and its old
   state.
5. **PHP-FPM is not safe by extension.** The observed "child exits with
   code 70" covers just one demonstrated path; the announcement lists
   every request-serving interface as affected, including plain FastCGI,
   FrankenPHP and LiteSpeed.
6. **Never use `RLIMIT_AS` or `RLIMIT_DATA`** as memory caps — an
   allocation failure induced by those limits is precisely the trigger
   this vulnerability needs.
7. **Web server limits must cover requests without Content-Length.** A
   POST sent with chunked transfer encoding can slip past a naive
   `post_max_size` check; enforce decoded-body limits at the proxy layer
   as well.
8. **Every failed attempt crashes a worker.** Segmentation-fault bursts
   mean the attack is *failing* — yet each attempt is also a probe of
   your defenses. Treat every occurrence as a security incident, not
   noise.
9. **The session-poisoning trick outlives these CVEs.** Storing PHP code
   inside a session file via the upload file name, then pulling that file
   in through a local file inclusion (an application bug where a
   user-controlled path reaches `include`/`require`), still worked in our
   tests even on *patched* PHP versions. Audit your applications for
   user-influenced include paths no matter which PHP version you run.

---

## 7. One-page summary

| Question | Answer |
|---|---|
| Am I vulnerable? | Yes, if you serve web requests with PHP older than 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |
| First action | Upgrade PHP — no complete workaround exists |
| Next best | `session.upload_progress.enabled = Off` (at config level) and restart every worker |
| Also | `memory_limit = -1` as an admin value, a small `post_max_size`; never `RLIMIT_AS`/`RLIMIT_DATA` |
| PHP 8.5 only | Add `fatal_error_backtraces = Off` |
| Watch for | Segmentation-fault bursts, "Allowed memory size … in Unknown on line 0", FPM exit code 70, PHPSESSID cookies above 256 bytes, `<?php` inside session files |
