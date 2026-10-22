# php2shell exposure assessment (CVE-2026-109618 / CVE-2026-109619)

Authorized, **non-destructive** risk assessment for the PHP "php2shell"
vulnerabilities. It fingerprints the runtime, decides whether the vulnerable
code is reachable, explains the exploitation path, and prints prioritized
mitigations. It does **not** exploit the target.

## 1. What is php2shell

Two independent, pre-authentication remote-code-execution bugs in the PHP
engine request lifecycle, disclosed 2026-10-21 and rated **CVSS v4.0 9.2
(Critical)**.

| | CVE-2026-109618 | CVE-2026-109619 |
|---|---|---|
| Root cause | Out-of-memory handling calls `longjmp()` after the request allocator has freed/invalidated memory; the request exits through corrupted state | Request-owned global state survives shutdown and is reused by the next request on the same worker |
| Trigger | Oversized / malformed request that forces the parser through an OOM path (oversized part names, many file parts, bodies that bypass `max_file_uploads` accounting) | A "producer" request leaves state behind; a later "consumer" request on the same worker uses it |
| Scope | Applies across SAPIs; `mod_php` is the most reliable | Confirmed on PHP-FPM; needs producer/consumer to share a worker |
| Auth | None: the corruption happens during request initialization, before application code runs | None, but needs a suitable post-startup operation in the app |
| Auth bypass | Yes: framework middleware/auth never executes | Yes, same reason |

Reported affected range: **PHP 5.4 through 8.5.11**. Fixed releases:

- PHP **8.5.12**
- PHP **8.4.27**
- PHP **8.3.36**
- PHP **8.2.35**

PHP 8.1 and older are EOL and will not receive upstream binary fixes. They
require a distro/vendor backport or an upgrade.

Documented attack-side signals: oversized multipart part names, a
`PHPSESSID` that is much longer than the normal 26-32 bytes (a memory
disclosure oracle), `Allowed memory size ... exhausted ... in Unknown on line
0`, and worker segfaults/churn. A successful exploit can also return a plain
`200` without crashing the worker, so absence of crashes is not absence of
compromise.

## 2. What this tool does and does not do

**Does**

- Reads `Server` / `X-Powered-By` / cookies / error text to infer PHP version,
  SAPI, and CMS.
- Optionally parses an exposed `phpinfo()` page for the exact version,
  `Server API`, `memory_limit`, `post_max_size`, `display_errors`,
  `session.upload_progress.enabled`.
- Compares against the fixed versions.
- Sends one small multipart POST with `PHP_SESSION_UPLOAD_PROGRESS` and one
  ordinary urlencoded POST, then looks for the cookie/oracle signals.
- Produces `PATCHED / EXPOSED / LIKELY_EXPLOITABLE / UNDETERMINED / UNKNOWN`, the applicable
  CVE path, why, mitigations, and hunting guidance.

**Does not**

- Send an OOM payload, groom the heap, leak ASLR, or execute commands.
- Guarantee exploitability. A real chain is build-specific: it depends on the
  exact `libphp`/`php-fpm` build, `memory_limit` vs `post_max_size`, worker
  count and reuse, and an address leak. `EXPOSED` means *the vulnerable code is
  present and reachable*, not *one request will pop a shell*.
- Replace a host-side version check. If the banner is hidden, verify the
  package/image locally.

### Why there is no "URL in, shell out" script here

A generic URL-to-RCE tool for this bug would need per-build offsets,
reliable heap shaping, and an ASLR bypass, and it would be trivially reusable
against third parties. Several "PoC" repos circulating since disclosure are
lab-tuned, unverified, or malware lures. For a risk assessment the useful
question is *"is the vulnerable runtime exposed, and how do we remove it?"*,
which this tool answers safely.

## 3. Usage

```bash
cd /home/kali/php2shell-assessment
chmod +x php2shell_triage.py

# Basic: headers + benign probes
python3 php2shell_triage.py --url https://app.example.com/ --authorized

# Best signal: you have permission and a phpinfo() page in scope
python3 php2shell_triage.py \
  --url https://app.example.com/ \
  --phpinfo-path /phpinfo.php \
  --authorized --json result.json

# Fingerprint only, no POSTs
python3 php2shell_triage.py --url https://app.example.com/ --authorized --no-probes

# Self-signed / internal TLS
python3 php2shell_triage.py --url https://10.0.0.5/ --authorized --insecure

# Authenticated scope
python3 php2shell_triage.py --url https://app.example.com/ --authorized \
  --cookie 'PHPSESSID=...; other=...'
```

`--authorized` is required and is a confirmation, not a legal shield. Only run
this against systems you own or have written permission to test.

### Verdicts

| Verdict | Meaning | Action |
|---|---|---|
| `PATCHED` | Detected version is at/above the fixed release | Keep it; re-verify images and any second runtime |
| `LIKELY_EXPLOITABLE` | Vulnerable version, PHP endpoint, and either `mod_php` or a confirmed precondition | Treat as urgent; patch and hunt for prior exploitation |
| `EXPOSED` | Vulnerable version detected, SAPI not fully confirmed | Patch now; confirm SAPI on host |
| `UNDETERMINED` | PHP runtime confirmed (FPM/CGI error string, session cookie, or dynamic multipart), version hidden | **Not safe** — read the build on the host; patch if below the fixed releases |
| `UNKNOWN` | No version and no confirmed runtime (or newer than known branches) | Check the package/image locally; a hidden banner is not safety |
| `BLOCKED` | Edge/WAF challenge (Cloudflare 403/429/challenge) | Ask for an allowlist/WAF skip or test the origin; this is not a patch result |
| `UNREACHABLE` | No baseline response | Check network/TLS; retry with `--insecure` |

Confidence is `high` only when the version came from `phpinfo()`. The scanner
confirms a PHP backend without exploiting it: it requests a random non-existent
`.php` file and looks for PHP-FPM's `File not found.` (or php-cgi's `No input
file specified.`). That turns the common "nginx stripped every banner" case from
`UNKNOWN` into `UNDETERMINED` with `SAPI: php-fpm [backend confirmed]`.

## 4. Local lab (validate the detector, not attack third parties)

`lab/docker-compose.yml` runs two containers with identical config:

- `php:8.5.11-apache` on `http://127.0.0.1:8088` (vulnerable)
- `php:8.5.12-apache` on `http://127.0.0.1:8089` (patched)

```bash
cd /home/kali/php2shell-assessment/lab
docker compose up -d
docker compose ps

# Both reachable
curl -s http://127.0.0.1:8088/ ; echo
curl -s http://127.0.0.1:8089/ ; echo

# Expect LIKELY_EXPLOITABLE vs PATCHED
python3 ../php2shell_triage.py --url http://127.0.0.1:8088/ --authorized \
  --phpinfo-path /phpinfo.php
python3 ../php2shell_triage.py --url http://127.0.0.1:8089/ --authorized \
  --phpinfo-path /phpinfo.php
```

If the `php:8.5.11-apache` / `php:8.5.12-apache` tags are unavailable in your
registry mirror, change the tags in `docker-compose.yml` to the closest
available 8.x builds and adjust expectations. `phpinfo.php` exists only in the
lab; never ship it.

### Behind Cloudflare or another WAF

The scanner detects `server: cloudflare` / `cf-ray` and reports `BLOCKED` for a
challenge instead of guessing a verdict. It also adds a random `cb=` cache
buster to every request so an edge-cached 404 cannot mask the origin.

With the owner's permission, reach the origin directly while keeping the real
Host header and TLS SNI:

```bash
python3 php2shell_triage.py --url https://app.example.com/ --authorized \
  --resolve app.example.com:443:203.0.113.10
```

Or use an owner-supplied test header / allowlisted egress IP:

```bash
python3 php2shell_triage.py --url https://app.example.com/ --authorized \
  --header 'X-Test-Token: <owner-token>'
```

Other flags: `--user-agent`, `--no-cache-buster`. Do not rotate IPs or user
agents to evade a WAF; get an allowlist instead. If the origin is only
reachable through Cloudflare Tunnel or Authenticated Origin Pulls, `--resolve`
cannot help and the owner must provide an unproxied staging hostname.

### Front-proxy / PHP-FPM lab

Real targets usually put nginx in front of PHP-FPM, and many disable
`expose_php`, which hides `X-Powered-By`. `lab/docker-compose.fpm.yml`
reproduces that:

- `php:8.5.11-fpm` behind nginx on `http://127.0.0.1:18090`
- `php:8.5.12-fpm` behind nginx on `http://127.0.0.1:18091`
- `php:8.5.11-fpm` with `expose_php=Off` on `http://127.0.0.1:18092`

```bash
cd /home/kali/php2shell-assessment/lab
docker compose -f docker-compose.fpm.yml -p php2shell-fpm up -d

python3 ../php2shell_triage.py --url http://127.0.0.1:18090/ --authorized   # LIKELY_EXPLOITABLE
python3 ../php2shell_triage.py --url http://127.0.0.1:18091/ --authorized   # PATCHED
python3 ../php2shell_triage.py --url http://127.0.0.1:18092/ --authorized   # UNDETERMINED + php-fpm confirmed

docker compose -f docker-compose.fpm.yml -p php2shell-fpm down
```

Ports 18090-18092 are used to avoid collisions; edit the compose file if needed.
`nginx-patched.conf` / `nginx-hidden.conf` point each vhost at its own pool.

To stop the Apache lab:

```bash
docker compose down
```

## 5. Remediation checklist

1. **Patch.** Upgrade to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or a vendor
   backport. Rebuild images, redeploy, and restart **every** PHP worker
   (`systemctl restart php8.x-fpm apache2`, rolling restarts included).
2. **Confirm the running binary**, not just the package: `php -v`,
   `php -i | grep -E 'Version|Server API'`, and the container image digest.
3. **Edge controls, interim only.** Cap decoded body size, rate-limit POSTs,
   and block `multipart/form-data` where uploads are not needed. Do not rely on
   a WAF alone; see `rules/`.
4. **PHP config, interim.**
   - `memory_limit=-1` with container/cgroup limits. Do **not** use
     `RLIMIT_AS`/`RLIMIT_DATA`, which reintroduce OOM/abort behavior.
   - `session.upload_progress.enabled=0` where unused.
   - On 8.5, `fatal_error_backtraces=0`.
   - Restart all workers after INI changes.
5. **PHP-FPM.** `pm.max_requests=1` if throughput allows: it breaks the
   producer/consumer same-worker requirement for CVE-2026-109619.
6. **Remove early diagnostics.** Per-request INI overrides in `.htaccess` /
   `php_value` / `PHP_VALUE` that emit diagnostics during initialization.
7. **Isolate what you cannot patch.** Put it behind ZTNA/network ACL, or take
   it offline. Internet-facing unpatched PHP is the priority.
8. **Hunt before you patch.** Assume compromise if the host was exposed and
   internet-facing: review web/PHP/Apache logs for the signals in section 1,
   inspect for web-user shell children, new cron/systemd units, `authorized_keys`
   changes, and outbound connections. Rotate secrets the web user could read.

## 6. Detection assets

- `rules/README.md`: ModSecurity, nginx, Suricata, log-hunt commands,
  PHPSESSID-length oracle query.
- `rules/sigma-web-worker-shell.yml`: process-ancestry rule for a web worker
  spawning a shell/downloader.
- `php2shell_triage.py → DETECTION` section: the same signals in report form.

The strongest single detection is the error-log line
`Allowed memory size ... exhausted ... in Unknown on line 0`, because it means
memory died during request initialization, before any script line executed.

## 7. References

- Datadog Security Labs — php2shell technical analysis and remediation:
  https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/
- php-src advisory GHSA-w8hw-w9fx-j79w (OOM corruption, patch versions):
  https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- CISA alert, 2026-10-21 (internet-facing PHP, urgent patching).
- Canadian Centre for Cyber Security bulletin AL26-026.
- NCSC-NL operational guidance: https://github.com/NCSC-NL/php2shell
- Public PoC repos (reference only; unverified and build-specific):
  `Whackermelon/Php2Shell-POC`, `xuehuolll/php2shell-CVE-2026-109618-109619`.
  Do not install or run tooling from these repos on production or privileged
  hosts without review; the disclosure window has already produced malicious
  look-alike packages.

## 8. Authorized use

This tool is for owners and authorized assessors of the target. Running it
against third-party systems without written permission may be unlawful. The
`--authorized` flag records your confirmation; it does not grant permission.
