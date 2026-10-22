#!/usr/bin/env python3
"""
php2shell (CVE-2026-109618 / CVE-2026-109619) authorized exposure triage.

WHAT THIS DOES
  * Fingerprints the PHP runtime behind a URL (version, SAPI hints, error
    disclosure, session cookies, CMS).
  * Optionally reads an exposed phpinfo() page to obtain the exact runtime
    configuration.
  * Sends only small, benign requests. It does NOT trigger the OOM condition,
    does NOT perform heap grooming, and ships no exploit.
  * If you pass --verify-exec, it can hand the URL to a verifier you supply
    (e.g. your own authorized PoC) and show the harmless id/whoami output.
  * Produces a verdict: PATCHED / EXPOSED / LIKELY_EXPLOITABLE / UNDETERMINED /
    BLOCKED / UNKNOWN,
    the exploitation path that applies, and prioritized mitigations.

WHAT THIS DOES NOT DO
  * It is not an exploit and contains no RCE payload. A real php2shell exploit
    is target-specific (build offsets, ASLR leak, memory_limit/post_max_size
    ratio, worker reuse). --verify-exec only orchestrates a verifier you
    already have, under an explicit host allowlist.

REQUIRES WRITTEN AUTHORIZATION for the target. Use --authorized to confirm.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Any

FIXED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

UA = "php2shell-triage/1.0 (+authorized risk assessment)"

# Set from CLI before any request. RESOLVE maps a hostname to an origin IP so the
# scanner can reach an origin directly while keeping the Host header and SNI.
RESOLVE: dict[str, str] = {}
EXTRA_HEADERS: dict[str, str] = {}
CACHE_BUST = True

BANNER = r"""
+------------------------------------------------------------------+
|  php2shell triage  CVE-2026-109618 / CVE-2026-109619             |
|  NON-DESTRUCTIVE exposure check. Authorized targets only.       |
+------------------------------------------------------------------+
"""


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def eprint(*a: Any) -> None:
    print(*a, file=sys.stderr)


def parse_version(text: str) -> tuple[int, ...] | None:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def version_status(v: tuple[int, ...] | None) -> tuple[str, str | None]:
    """Return (status, fixed_version). status in fixed/vulnerable/vulnerable_eol/unknown."""
    if v is None:
        return "unknown", None
    mm = (v[0], v[1])
    if mm in FIXED:
        fixed = FIXED[mm]
        if v >= fixed:
            return "fixed", ".".join(map(str, fixed))
        return "vulnerable", ".".join(map(str, fixed))
    if v < (8, 2):
        if v >= (5, 4):
            return "vulnerable_eol", "no upstream binary fix (EOL branch)"
        return "unknown", None
    if v >= (8, 6):
        return "unknown_newer", None
    return "unknown", None


def norm_url(url: str) -> str:
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    return url


def cache_bust(url: str) -> str:
    if not CACHE_BUST:
        return url
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    q.append(("cb", uuid.uuid4().hex[:12]))
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(q)))


class _ResolvedHTTPConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        ip = RESOLVE.get((self.host or "").lower())
        if not ip:
            return super().connect()
        self.sock = socket.create_connection((ip, self.port), self.timeout, self.source_address)


class _ResolvedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self) -> None:
        ip = RESOLVE.get((self.host or "").lower())
        if not ip:
            return super().connect()
        sock = socket.create_connection((ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
            sock = self.sock
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _ResolvedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_ResolvedHTTPConnection, req)


class _ResolvedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context: ssl.SSLContext):
        super().__init__(context=context)

    def https_open(self, req):
        return self.do_open(_ResolvedHTTPSConnection, req, context=self._context,
                            check_hostname=self._check_hostname)


def _opener(ctx: ssl.SSLContext) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_ResolvedHTTPHandler(), _ResolvedHTTPSHandler(ctx))


def req(url: str, *, method: str = "GET", body: bytes | None = None,
        headers: dict[str, str] | None = None, timeout: float = 15.0,
        insecure: bool = False) -> dict[str, Any]:
    h = {"User-Agent": UA, "Accept": "*/*", "Connection": "close"}
    h.update(EXTRA_HEADERS)
    if headers:
        h.update(headers)
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    url = cache_bust(url)
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    t0 = time.time()
    try:
        with _opener(ctx).open(r, timeout=timeout) as resp:
            raw = resp.read(512_000)
            return {
                "ok": True,
                "status": resp.status,
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "set_cookie": resp.headers.get_all("Set-Cookie") or [],
                "body": raw.decode("utf-8", "replace"),
                "raw_len": len(raw),
                "elapsed": round(time.time() - t0, 3),
                "url": resp.geturl(),
                "error": None,
            }
    except urllib.error.HTTPError as e:
        raw = b""
        try:
            raw = e.read(512_000)
        except Exception:
            pass
        return {
            "ok": True,
            "status": e.code,
            "headers": {k.lower(): v for k, v in (e.headers or {}).items()},
            "set_cookie": (e.headers.get_all("Set-Cookie") if e.headers else []) or [],
            "body": raw.decode("utf-8", "replace"),
            "raw_len": len(raw),
            "elapsed": round(time.time() - t0, 3),
            "url": e.geturl(),
            "error": None,
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "elapsed": round(time.time() - t0, 3)}


def multipart(fields: dict[str, str], files: dict[str, tuple[str, bytes, str]] | None = None) -> tuple[bytes, str]:
    b = "----php2shell" + uuid.uuid4().hex
    out = bytearray()
    for name, value in fields.items():
        out += f"--{b}\r\n".encode()
        out += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        out += value.encode() + b"\r\n"
    for name, (fname, data, ctype) in (files or {}).items():
        out += f"--{b}\r\n".encode()
        out += f'Content-Disposition: form-data; name="{name}"; filename="{fname}"\r\n'.encode()
        out += f"Content-Type: {ctype}\r\n\r\n".encode()
        out += data + b"\r\n"
    out += f"--{b}--\r\n".encode()
    return bytes(out), f"multipart/form-data; boundary={b}"


def cookie_names(set_cookie: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for c in set_cookie:
        first = c.split(";", 1)[0]
        if "=" in first:
            k, v = first.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def pct_len(s: str) -> int:
    try:
        return len(urllib.parse.unquote(s))
    except Exception:
        return len(s)


# --------------------------------------------------------------------------
# assessment
# --------------------------------------------------------------------------

@dataclass
class Finding:
    key: str
    value: Any
    note: str = ""


@dataclass
class Assessment:
    target: str
    started: str
    reachable: bool = False
    status: int | None = None
    server: str = ""
    powered_by: str = ""
    edge: str = ""
    blocked: bool = False
    block_reason: str = ""
    php_version_text: str = ""
    php_version: tuple[int, ...] | None = None
    version_source: str = "none"
    version_status: str = "unknown"
    fixed_version: str | None = None
    sapi: str = "unknown"
    fpm_confirmed: bool = False
    fpm_evidence: str = ""
    php_cookie_seen: bool = False
    set_cookie_names: list[str] = field(default_factory=list)
    cms: str = "unknown"
    php_endpoint: bool = False
    multipart_accepted: bool | None = None
    upload_progress_cookie: str | None = None
    phpsessid_len: int | None = None
    long_session_cookie: bool = False
    memory_error_seen: bool = False
    display_errors: bool | None = None
    phpinfo: dict[str, str] | None = None
    session_upload_progress: str | None = None
    memory_limit: str | None = None
    post_max_size: str | None = None
    max_requests_known: bool = False
    findings: list[Finding] = field(default_factory=list)
    verdict: str = "UNKNOWN"
    confidence: str = "low"
    exploit_paths: list[str] = field(default_factory=list)
    why: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    verification: dict[str, Any] | None = None


def edge_block(r: dict[str, Any]) -> tuple[bool, str]:
    """Classify an edge (Cloudflare/Akamai/etc.) block page, not an app response."""
    if not r.get("ok"):
        return False, ""
    h = r.get("headers", {})
    body = (r.get("body") or "")[:6000].lower()
    status = r.get("status")
    cf = "cf-ray" in h or "cloudflare" in h.get("server", "").lower()
    if h.get("cf-mitigated", "").lower() in ("challenge", "managed_challenge"):
        return True, "Cloudflare challenge (cf-mitigated)"
    if cf and status in (403, 429, 503):
        return True, f"HTTP {status} from the Cloudflare edge"
    if "just a moment" in body or "attention required" in body or "cf-chl" in body:
        return True, "Cloudflare challenge page in the body"
    return False, ""


def fingerprint(a: Assessment, base: str, timeout: float, insecure: bool) -> None:
    r = req(base, timeout=timeout, insecure=insecure)
    if not r.get("ok"):
        a.errors.append(f"baseline request failed: {r.get('error')}")
        return
    a.reachable = True
    a.status = r["status"]
    h = r["headers"]
    a.server = h.get("server", "")
    a.powered_by = h.get("x-powered-by", "")
    if "cloudflare" in a.server.lower() or "cf-ray" in h:
        a.edge = "cloudflare"
    blocked, why = edge_block(r)
    if blocked:
        a.blocked = True
        a.block_reason = why
    body = r.get("body", "")
    low = body.lower()

    # version hints: header > phpinfo-style table > error text > generic body.
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", a.powered_by, re.I)
    if m:
        a.php_version_text = m.group(1)
        a.version_source = "x-powered-by"
    if not a.php_version_text:
        m = re.search(r"PHP Version\s*</td>\s*<td[^>]*>\s*([0-9.]+)", body, re.I | re.S)
        if m:
            a.php_version_text = m.group(1)
            a.version_source = "body-phpinfo"
    if not a.php_version_text:
        m = re.search(r"PHP\s+(\d+\.\d+\.\d+)", body, re.I)
        if m and ("fatal error" in low or "warning" in low or "php" in low):
            a.php_version_text = m.group(1)
            a.version_source = "error-text"
    if not a.php_version_text:
        m = re.search(r'"(?:php|php_version)"\s*:\s*"(\d+\.\d+\.\d+)"', body, re.I)
        if m:
            a.php_version_text = m.group(1)
            a.version_source = "body-json"
    a.php_version = parse_version(a.php_version_text)
    a.version_status, a.fixed_version = version_status(a.php_version)

    # cookies: a PHP session cookie confirms the runtime even when headers hide it.
    ck = cookie_names(r["set_cookie"])
    a.set_cookie_names = list(ck.keys())
    php_cookie_keys = ("PHPSESSID", "laravel_session", "wordpress_", "wp-settings-", "drupal",
                       "ci_session", "cakephp", "yii_", "symfony", "sid_")
    for k, v in ck.items():
        if k in php_cookie_keys or k.startswith(php_cookie_keys):
            if len(v) >= 16:
                a.php_cookie_seen = True
                a.findings.append(Finding("php_session_cookie", k,
                                          "PHP-style session cookie (custom session.name); weak runtime evidence"))

    # PHP endpoint / SAPI hints
    php_markers = ("phpsessid", "x-powered-by: php", "php version", "fatal error",
                   "warning:", "notice:", "allowed memory size", "phpinfo")
    a.php_endpoint = (
        "php" in a.powered_by.lower()
        or a.php_cookie_seen
        or re.search(r"\.php(?:[?#\"']|$)", base, re.I) is not None
        or any(x in low for x in php_markers)
    )
    if "mod_php" in low or "apache" in a.server.lower():
        a.sapi = "apache/mod_php (probable)"
    if "php-fpm" in low or "fpm-fcgi" in low:
        a.sapi = "php-fpm"
    if "litespeed" in a.server.lower():
        a.sapi = "litespeed"

    # CMS
    for name, sig in (
        ("WordPress", ("wp-content", "wp-includes", "/wp-json")),
        ("Drupal", ("drupal", "sites/default/files", "x-generator: drupal")),
        ("Joomla", ("joomla", "/media/system/js/", "option=com_")),
        ("Laravel", ("laravel_session", "x-powered-by: php")),
        ("Symfony", ("symfony", "sf_redirect")),
    ):
        if any(s in low for s in sig):
            a.cms = name
            break

    if "display_errors" in low and ("on" in low or "off" in low):
        a.display_errors = None  # ambiguous; only trust phpinfo
    if "allowed memory size" in low:
        a.memory_error_seen = True
        a.findings.append(Finding("memory_error", True, "Memory exhaustion message visible in baseline response"))

    if "PHPSESSID" in ck:
        a.phpsessid_len = pct_len(ck["PHPSESSID"])
        if a.phpsessid_len > 40:
            a.long_session_cookie = True
            a.findings.append(Finding("long_phpsessid", a.phpsessid_len,
                                      "PHPSESSID longer than a normal 26-32 byte ID (memory-disclosure indicator)"))


def probe_runtime(a: Assessment, base: str, timeout: float, insecure: bool) -> None:
    """Confirm the SAPI without exploiting anything.

    A missing .php script is handed to the FastCGI backend by nginx/Apache. The
    backend's own error string ("File not found." from PHP-FPM, "No input file
    specified." from php-cgi) proves a PHP runtime is behind the proxy even when
    every version banner is stripped.
    """
    name = f"php2shell-{uuid.uuid4().hex[:10]}.php"
    url = urllib.parse.urljoin(base, name)
    r = req(url, timeout=timeout, insecure=insecure)
    if not r.get("ok"):
        a.errors.append(f"runtime probe failed: {r.get('error')}")
        return
    body = r.get("body", "")
    low = body.lower()
    h = r.get("headers", {})
    px = h.get("x-powered-by", "")

    if "file not found" in low:
        a.fpm_confirmed = True
        a.fpm_evidence = body.strip()[:160] or "File not found."
        a.sapi = "php-fpm"
        a.findings.append(Finding("fpm_confirmed", True,
                                  "Missing .php script returned the PHP-FPM 'File not found.' error"))
    elif "no input file specified" in low:
        a.fpm_confirmed = True
        a.fpm_evidence = body.strip()[:160]
        a.sapi = "php-cgi"
        a.findings.append(Finding("cgi_confirmed", True,
                                  "Missing .php script returned 'No input file specified.'"))
    elif "php" in px.lower():
        a.fpm_confirmed = True
        a.fpm_evidence = f"X-Powered-By: {px}"
        if a.sapi == "unknown":
            a.sapi = "php-fpm (behind proxy)"
        a.findings.append(Finding("php_backend_confirmed", px,
                                  "Backend exposed a PHP X-Powered-By on the missing-script probe"))
    elif a.php_cookie_seen:
        a.findings.append(Finding("php_cookie_confirmed", True,
                                  "PHP session cookie confirms a PHP runtime"))
    elif "nginx" in a.server.lower() and "nginx" in low:
        a.errors.append("Missing .php returned the nginx 404 page: static-only vhost or a catch-all route. "
                        "Runtime not confirmed by this probe.")

    if a.fpm_confirmed:
        a.php_endpoint = True


def read_phpinfo(a: Assessment, base: str, path: str, timeout: float, insecure: bool) -> None:
    url = urllib.parse.urljoin(base, path)
    r = req(url, timeout=timeout, insecure=insecure)
    if not r.get("ok") or r["status"] != 200:
        a.errors.append(f"phpinfo path {path!r} not readable (status={r.get('status')})")
        return
    body = r.get("body", "")
    if "phpinfo()" not in body.lower() and "php version" not in body.lower():
        a.errors.append(f"{path!r} did not look like phpinfo()")
        return
    info: dict[str, str] = {}
    for key in ("PHP Version", "Server API", "Loaded Configuration File", "memory_limit",
                "post_max_size", "display_errors", "file_uploads",
                "session.upload_progress.enabled", "max_file_uploads",
                "session.save_path", "opcache.enable"):
        m = re.search(
            r'<td class="e">\s*' + re.escape(key) + r'\s*</td>\s*<td class="v">(.*?)</td>',
            body, re.I | re.S,
        )
        if m:
            info[key] = re.sub(r"<[^>]+>", "", m.group(1)).strip()
    a.phpinfo = info
    if "PHP Version" in info:
        a.php_version_text = info["PHP Version"]
        a.version_source = "phpinfo"
        a.php_version = parse_version(a.php_version_text)
        a.version_status, a.fixed_version = version_status(a.php_version)
    if "Server API" in info:
        sapi = info["Server API"].lower()
        if "apache" in sapi:
            a.sapi = "apache/mod_php"
        elif "fpm" in sapi:
            a.sapi = "php-fpm"
        elif "cgi" in sapi:
            a.sapi = "php-cgi"
        elif "litespeed" in sapi:
            a.sapi = "litespeed"
        else:
            a.sapi = info["Server API"]
    a.session_upload_progress = info.get("session.upload_progress.enabled")
    a.memory_limit = info.get("memory_limit")
    a.post_max_size = info.get("post_max_size")
    if info.get("display_errors"):
        a.display_errors = info["display_errors"].lower().startswith("on")


def benign_probes(a: Assessment, base: str, timeout: float, insecure: bool) -> None:
    # 1. multipart with the upload-progress trigger field, tiny payload.
    body, ctype = multipart(
        {"PHP_SESSION_UPLOAD_PROGRESS": f"triage|{uuid.uuid4().hex}"},
        {"file": ("triage.txt", b"triage", "text/plain")},
    )
    r = req(base, method="POST", body=body,
            headers={"Content-Type": ctype, "Cookie": "PHPSESSID=" + uuid.uuid4().hex},
            timeout=timeout, insecure=insecure)
    if r.get("ok"):
        a.multipart_accepted = r["status"] not in (400, 405, 413, 415, 501)
        ck = cookie_names(r["set_cookie"])
        if "PHPSESSID" in ck:
            a.upload_progress_cookie = ck["PHPSESSID"]
            n = pct_len(ck["PHPSESSID"])
            if n > 40:
                a.long_session_cookie = True
                a.findings.append(Finding("long_phpsessid_probe", n,
                                          "Probe response issued an abnormally long PHPSESSID"))
        if "allowed memory size" in r.get("body", "").lower():
            a.memory_error_seen = True

    # 2. ordinary urlencoded POST with nested field syntax (normal parser path).
    r2 = req(base, method="POST", body=b"a=1&probe%5Bx%5D=1",
             headers={"Content-Type": "application/x-www-form-urlencoded"},
             timeout=timeout, insecure=insecure)
    if r2.get("ok") and r2["status"] >= 500:
        a.findings.append(Finding("post_5xx", r2["status"], "Benign POST returned a server error"))


def decide(a: Assessment) -> None:
    reasons: list[str] = []
    paths: list[str] = []
    conf = "low"

    if not a.reachable:
        a.verdict = "UNREACHABLE"
        a.confidence = "n/a"
        a.why.append("Target did not respond to the baseline request.")
        a.mitigations.append("Re-run with --insecure for self-signed TLS or check network path.")
        return

    if a.blocked:
        a.verdict = "BLOCKED"
        a.confidence = "n/a"
        a.why.append(f"An edge/WAF blocked the request: {a.block_reason}"
                     + (f" (edge: {a.edge})" if a.edge else "") + ".")
        a.why.append("This is not evidence of a patch or a vulnerability; the scanner never reached the PHP "
                     "runtime.")
        a.mitigations = [
            "Ask the owner to allowlist your egress IP or add a WAF skip rule for the test window.",
            "Or use an unproxied staging hostname / origin address supplied by the owner (--resolve HOST:PORT:IP).",
            "If the owner allows a test header, pass it with --header 'X-Test-Token: ...'.",
            "Then re-run; do not raise the request rate or rotate user agents to evade the control.",
        ]
        return

    vs = a.version_status
    if vs == "fixed":
        a.verdict = "PATCHED"
        conf = "high" if a.phpinfo else "medium"
        reasons.append(f"Detected PHP {a.php_version_text}, at/above the fixed release {a.fixed_version}.")
        if a.phpinfo:
            reasons.append("Version came from an exposed phpinfo() page, so it reflects the web SAPI.")
        else:
            reasons.append("Version was inferred from headers/body; verify on the host if it is hidden or proxied.")
    elif vs in ("vulnerable", "vulnerable_eol"):
        conf = "high" if a.phpinfo else ("medium" if a.php_version else "low")
        reasons.append(f"Detected PHP {a.php_version_text}, below the fixed release {a.fixed_version}.")
        if vs == "vulnerable_eol":
            reasons.append("PHP branch is EOL; no upstream binary fix. Vendor backport or upgrade required.")
        a.verdict = "EXPOSED"
        if a.sapi.startswith("apache/mod_php"):
            a.verdict = "LIKELY_EXPLOITABLE"
            paths.append(
                "CVE-2026-109618 (OOM corruption): unauthenticated multipart/urlencoded request can corrupt "
                "request-initialization state and reach remote code execution during shutdown, before any "
                "application code or authentication runs. mod_php is the highest-risk SAPI."
            )
            paths.append(
                "CVE-2026-109619 (stale global state): a producer request leaves request-owned state behind and "
                "a later request on the same worker consumes it; exploitation needs same-worker reuse."
            )
        elif a.sapi.startswith("php-fpm"):
            a.verdict = "LIKELY_EXPLOITABLE"
            paths.append(
                "CVE-2026-109619: confirmed RCE on PHP-FPM when the application performs a suitable operation "
                "after startup; producer and consumer requests must land on the same worker."
            )
            paths.append(
                "CVE-2026-109618: source analysis indicates FPM susceptibility, though a complete public FPM "
                "chain is less reliable than mod_php."
            )
        else:
            paths.append(
                "Both CVEs are in the PHP core request lifecycle and apply to mod_php, PHP-FPM, php-cgi, "
                "FrankenPHP and LiteSpeed. Confirm the SAPI locally; mod_php is the most reliably exploitable."
            )
        if a.multipart_accepted:
            reasons.append("The endpoint accepts multipart/form-data, one of the request paths used to reach the "
                           "vulnerable parser.")
        if a.session_upload_progress and a.session_upload_progress.lower().startswith("on"):
            reasons.append("session.upload_progress.enabled=On (factory default) is an exploitation precondition.")
        if a.long_session_cookie:
            reasons.append("An abnormally long PHPSESSID was observed; this is the documented memory-disclosure "
                           "oracle, not proof of RCE by itself.")
        reasons.append("Exploitation is still build-specific: it needs correct memory sizing, an ASLR/address "
                       "leak, and (for 109619) same-worker reuse. 'EXPOSED' means the vulnerable code is present, "
                       "not that a one-request exploit is guaranteed.")
    elif vs == "unknown_newer":
        a.verdict = "UNKNOWN"
        reasons.append(f"Detected PHP {a.php_version_text}, newer than the known fixed branches; verify the vendor "
                       "backport status.")
    else:
        runtime_confirmed = a.fpm_confirmed or a.php_cookie_seen or (a.php_endpoint and a.multipart_accepted)
        if runtime_confirmed:
            a.verdict = "UNDETERMINED"
            conf = "medium" if (a.fpm_confirmed or a.php_cookie_seen) else "low"
            reasons.append("A PHP runtime is confirmed"
                           + (" (PHP-FPM/CGI backend)" if a.fpm_confirmed else "")
                           + ", but the version is hidden: expose_php is off and/or the proxy strips "
                             "X-Powered-By and Server detail.")
            if a.fpm_confirmed:
                reasons.append(f"Runtime evidence: {a.fpm_evidence}")
            reasons.append("UNDETERMINED is NOT 'safe'. If this host runs PHP below 8.5.12 / 8.4.27 / "
                           "8.3.36 / 8.2.35, or any EOL branch, it is exposed; the tool simply cannot read "
                           "the version from the network.")
            paths.append(
                "If the host is unpatched, both CVEs apply. With nginx in front, PHP-FPM is the likely SAPI: "
                "CVE-2026-109619 needs producer+consumer requests on the same worker, and CVE-2026-109618 is "
                "assessed as FPM-susceptible but less reliable than mod_php."
            )
        else:
            a.verdict = "UNKNOWN"
            reasons.append("Could not determine the PHP version remotely. Absence of a version banner is not "
                           "evidence of safety; check the host/container image or an authorized phpinfo() page.")
            if a.php_endpoint:
                reasons.append("The target does behave like a PHP endpoint (cookies/headers/error text), so local "
                               "verification is warranted.")

    if a.cms != "unknown":
        reasons.append(f"Application fingerprint: {a.cms}. The flaw is in PHP itself, so updating the CMS alone "
                       "does not fix it.")
    if a.memory_error_seen:
        reasons.append("A memory-exhaustion message was visible, which is one of the documented attack-side "
                       "signals. Correlate with oversized POSTs and worker crashes.")

    a.why = reasons
    a.exploit_paths = paths
    a.confidence = conf
    if a.verdict == "PATCHED":
        a.mitigations = [
            "No php2shell patch action needed on this runtime, but confirm the version on the host/container "
            "image and on every other PHP runtime (CLI, cron, second vhost, worker pool).",
            "Keep image digests pinned to patched releases and add a deployment check that rejects "
            "8.5.<12, 8.4.<27, 8.3.<36, 8.2.<35.",
            "If any second runtime is older, patch it and restart its workers.",
            "Retain the edge caps (body size, POST rate limits) as defense in depth.",
            "If the host was exposed before patching, still hunt the signals below for prior exploitation.",
        ]
    elif a.verdict == "UNDETERMINED":
        a.mitigations = [
        "PRIMARY: check the version on the host/container now: php -v, php -i | grep -E 'Version|Server API', "
        "and the image digest. With nginx in front, the runtime is the php-fpm pool's PHP build.",
        "If below 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (or an EOL branch), patch and restart the FPM master "
        "and all workers.",
        "Try an authorized phpinfo()/health endpoint once: --enumerate-phpinfo or --phpinfo-path /phpinfo.php.",
        "Apply the edge caps and FPM pm.max_requests=1 now, while you verify the build.",
        "A hidden banner is not a fix: stripping X-Powered-By does not remove the vulnerable code.",
        ]
    elif a.verdict == "UNKNOWN":
        a.mitigations = [
        "PRIMARY: enumerate the runtime from the host or container image; the network gives no version.",
        "Test an authorized phpinfo() page or vendor health endpoint, and check every PHP runtime "
        "(vhost, CLI, cron, worker pool).",
        "Until the build is known, apply the edge caps (body size, POST rate limits, block unused multipart).",
        "If the runtime turns out to be below 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (or EOL), patch and restart "
        "all workers.",
        ]
    else:
        a.mitigations = [
        "PRIMARY: upgrade PHP to 8.5.12, 8.4.27, 8.3.36, or 8.2.35 (or a vendor backport), then rebuild images "
        "and restart every worker. This is the only complete fix.",
        "Edge: block multipart/form-data if the app does not need uploads; otherwise cap decoded body size and "
        "rate-limit POSTs at the reverse proxy/WAF. Also block the PHP_SESSION_UPLOAD_PROGRESS field where "
        "uploads are not used. Do not rely on a WAF alone.",
        "PHP config (interim): memory_limit=-1 (with container/cgroup limits, not RLIMIT_AS/RLIMIT_DATA); "
        "session.upload_progress.enabled=0; on 8.5, fatal_error_backtraces=0. Restart all workers after changes.",
        "PHP-FPM: set pm.max_requests=1 if performance permits, breaking the producer/consumer same-worker link.",
        "Reduce post_max_size to the smallest value the application needs; reject requests without a usable "
        "Content-Length.",
        "Remove per-request INI overrides (.htaccess/php_value/PHP_VALUE) that generate early diagnostics.",
        "Isolate internet-facing PHP that cannot be patched (ZTNA / network ACL / take offline).",
    ]
    a.detection = [
        "Web/proxy logs: unusually long form field names (MB-scale), raw NUL/control bytes in form bodies, "
        "multipart POSTs carrying PHP_SESSION_UPLOAD_PROGRESS, and bursts of POSTs from one source.",
        "PHP error log: 'Allowed memory size ... exhausted ... in Unknown on line 0' (failure during request "
        "initialization, before the script), especially correlated with large POSTs.",
        "Apache/FPM logs: worker segfaults (AH00052 / signal 11), unexpected worker churn, repeated 500s.",
        "Response anomaly: Set-Cookie PHPSESSID values far longer than 26-32 bytes (memory-disclosure oracle).",
        "Process telemetry: a web worker (www-data/apache/nginx) spawning sh/bash/curl/wget or outbound "
        "connections it never normally makes. In a successful exploit the worker may NOT crash and may return 200.",
        "Hunt for post-disclosure scanning and fake 'PoC' delivery (malicious GitHub/npm/PyPI packages) in the "
        "same window.",
    ]


# --------------------------------------------------------------------------
# optional proof-of-execution harness (bring your own verifier)
# --------------------------------------------------------------------------

def host_is_scoped(host: str, allow_hosts: list[str]) -> tuple[bool, str]:
    if not host:
        return False, "target has no hostname"
    if host in allow_hosts:
        return True, f"{host} explicitly listed in --allow-host"
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        return False, f"cannot resolve {host}: {exc}"
    addrs = {info[4][0] for info in infos}
    if not addrs:
        return False, f"{host} did not resolve"
    if all(not ipaddress.ip_address(a).is_global for a in addrs):
        return True, f"{host} resolves only to loopback/private space"
    return False, (f"{host} resolves to public address(es) {sorted(addrs)}; "
                   "add it with --allow-host after confirming written authorization")


def verify_execution(a: Assessment, url: str, exe: str, allow_hosts: list[str],
                     timeout: float) -> None:
    v: dict[str, Any] = {"performed": False, "verifier": exe, "target": url}
    a.verification = v

    if a.verdict not in ("LIKELY_EXPLOITABLE", "EXPOSED"):
        v["reason"] = f"verdict is {a.verdict}; execution proof only runs for EXPLOITABLE/EXPOSED"
        return

    host = urllib.parse.urlsplit(url).hostname or ""
    ok, why = host_is_scoped(host, allow_hosts)
    v["scope_check"] = why
    if not ok:
        v["reason"] = why
        return

    path = shutil.which(exe) or (exe if os.path.isfile(exe) else None)
    if not path:
        v["reason"] = f"verifier not found: {exe}"
        return

    try:
        cp = subprocess.run([path, url], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        v["reason"] = f"verifier timed out after {timeout}s"
        return
    except OSError as exc:
        v["reason"] = f"verifier failed to start: {exc}"
        return

    out = (cp.stdout or "").strip()
    err = (cp.stderr or "").strip()
    v.update({
        "performed": True,
        "exit_code": cp.returncode,
        "stdout": out[:4000],
        "stderr": err[:1000],
        "stdout_sha256": hashlib.sha256(out.encode()).hexdigest(),
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    try:
        with open("verify-audit.log", "a", encoding="utf-8") as fh:
            fh.write(json.dumps({k: v[k] for k in
                                 ("time", "target", "verifier", "exit_code",
                                  "stdout_sha256", "scope_check")}) + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

def render(a: Assessment) -> str:
    L: list[str] = []
    L.append("=" * 78)
    L.append(f"php2shell triage :: {a.target}")
    L.append(f"time: {a.started}")
    L.append("=" * 78)
    L.append(f"VERDICT      : {a.verdict}   (confidence: {a.confidence})")
    L.append(f"PHP version  : {a.php_version_text or 'unknown'}"
             + (f"   (source: {a.version_source})" if a.version_source != "none" else ""))
    L.append(f"Fixed at     : {a.fixed_version or 'n/a'}")
    L.append(f"SAPI         : {a.sapi}" + ("   [backend confirmed]" if a.fpm_confirmed else ""))
    if a.fpm_evidence:
        L.append(f"Runtime proof: {a.fpm_evidence}")
    if a.set_cookie_names:
        L.append(f"Cookies      : {', '.join(a.set_cookie_names)}")
    L.append(f"CMS          : {a.cms}")
    L.append(f"HTTP         : {a.status}  server={a.server or '-'}  x-powered-by={a.powered_by or '-'}")
    if a.edge:
        L.append(f"Edge         : {a.edge}" + (f"  [BLOCKED: {a.block_reason}]" if a.blocked else ""))
    L.append(f"PHP endpoint : {a.php_endpoint}")
    L.append(f"multipart    : {a.multipart_accepted}")
    L.append(f"upload_prog  : {a.session_upload_progress or 'unknown'}")
    L.append(f"memory_limit : {a.memory_limit or 'unknown'}")
    L.append(f"post_max_size: {a.post_max_size or 'unknown'}")
    L.append(f"PHPSESSID len: {a.phpsessid_len if a.phpsessid_len is not None else 'n/a'}"
             + ("  <-- anomalous" if a.long_session_cookie else ""))
    if a.findings:
        L.append("")
        L.append("EVIDENCE")
        for f in a.findings:
            L.append(f"  - {f.key} = {f.value}  ({f.note})")
    if a.why:
        L.append("")
        L.append("WHY / HOW IT IS EXPLOITABLE")
        for x in a.why:
            L.append(f"  * {x}")
    if a.exploit_paths:
        L.append("")
        L.append("APPLICABLE ATTACK PATHS")
        for i, x in enumerate(a.exploit_paths, 1):
            L.append(f"  {i}. {x}")
    L.append("")
    L.append("MITIGATIONS (in order)")
    for i, x in enumerate(a.mitigations, 1):
        L.append(f"  {i}. {x}")
    L.append("")
    L.append("DETECTION / HUNTING")
    for x in a.detection:
        L.append(f"  - {x}")
    if a.verification:
        v = a.verification
        L.append("")
        L.append("PROOF OF EXECUTION (--verify-exec, user-supplied verifier)")
        if v.get("performed"):
            L.append(f"  verifier : {v.get('verifier')}")
            L.append(f"  exit code: {v.get('exit_code')}")
            if v.get("stdout"):
                L.append("  --- stdout ---")
                for line in v["stdout"].splitlines():
                    L.append(f"  {line}")
            if v.get("stderr"):
                L.append("  --- stderr ---")
                for line in v["stderr"].splitlines():
                    L.append(f"  {line}")
            L.append("  Note: an exit code of 0 and the output above are the verifier's claim; "
                     "correlate with server logs.")
        else:
            L.append(f"  not run: {v.get('reason')}")
            if v.get("scope_check"):
                L.append(f"  scope: {v['scope_check']}")
    if a.errors:
        L.append("")
        L.append("NOTES")
        for x in a.errors:
            L.append(f"  - {x}")
    L.append("")
    if a.verification and a.verification.get("performed"):
        L.append("SCOPE: triage + user-supplied proof of execution. Audit line written to verify-audit.log.")
    else:
        L.append("SCOPE: non-destructive triage only. No exploit payload was sent and no command was executed.")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="php2shell authorized exposure triage (non-destructive)")
    ap.add_argument("--url", required=True, help="Target base URL or PHP endpoint")
    ap.add_argument("--authorized", action="store_true",
                    help="Confirm you have written authorization to test this target (required)")
    ap.add_argument("--phpinfo-path", help="Optional known phpinfo() path, e.g. /phpinfo.php")
    ap.add_argument("--enumerate-phpinfo", action="store_true",
                    help="Try common phpinfo paths (adds requests)")
    ap.add_argument("--json", metavar="FILE", help="Write machine-readable results to FILE")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    ap.add_argument("--no-probes", action="store_true", help="Fingerprint only; send no POSTs")
    ap.add_argument("--cookie", help="Optional Cookie header for authenticated scope")
    ap.add_argument("--verify-exec", metavar="PATH",
                    help="User-supplied verifier run as: PATH <url>. Only for EXPLOITABLE/EXPOSED "
                         "and only on scoped hosts. No verifier is bundled.")
    ap.add_argument("--allow-host", action="append", default=[], metavar="HOST",
                    help="Explicitly scope an external hostname for --verify-exec (repeatable)")
    ap.add_argument("--verify-timeout", type=float, default=45.0)
    ap.add_argument("--resolve", action="append", default=[], metavar="HOST:PORT:IP",
                    help="Connect to an origin IP while keeping Host/SNI, e.g. "
                         "example.com:443:203.0.113.10 (repeatable)")
    ap.add_argument("--header", action="append", default=[], metavar="'Name: value'",
                    help="Extra header on every request (owner-supplied test token, etc.)")
    ap.add_argument("--user-agent", help="Override the User-Agent (owner-approved test traffic)")
    ap.add_argument("--no-cache-buster", action="store_true",
                    help="Do not append a random cb= query parameter to requests")
    args = ap.parse_args()

    eprint(BANNER)
    if not args.authorized:
        eprint("[!] Refusing to run: pass --authorized only if you own the target or have written permission.")
        return 2

    globals()["UA"] = args.user_agent or UA
    globals()["CACHE_BUST"] = not args.no_cache_buster
    for spec in args.resolve:
        try:
            host, port, ip = spec.rsplit(":", 2)
            int(port)
            ipaddress.ip_address(ip)
        except ValueError:
            ap.error(f"--resolve expects HOST:PORT:IP, got {spec!r}")
        RESOLVE[host.lower()] = ip
    for hdr in args.header:
        if ":" not in hdr:
            ap.error(f"--header expects 'Name: value', got {hdr!r}")
        k, v = hdr.split(":", 1)
        EXTRA_HEADERS[k.strip()] = v.strip()

    base = norm_url(args.url)
    a = Assessment(target=base, started=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    if args.cookie:
        # apply to all requests by monkey-patching default headers via closure
        orig = req

        def req_with_cookie(url, **kw):  # type: ignore[no-untyped-def]
            h = dict(kw.pop("headers", {}) or {})
            h.setdefault("Cookie", args.cookie)
            return orig(url, headers=h, **kw)

        globals()["req"] = req_with_cookie  # noqa: PLW0603

    fingerprint(a, base, args.timeout, args.insecure)
    if a.reachable and not a.blocked and not args.no_probes:
        probe_runtime(a, base, args.timeout, args.insecure)

    if a.blocked:
        pass
    elif args.phpinfo_path:
        read_phpinfo(a, base, args.phpinfo_path, args.timeout, args.insecure)
    elif args.enumerate_phpinfo:
        for p in ("/phpinfo.php", "/info.php", "/php_info.php", "/test.php"):
            read_phpinfo(a, base, p, args.timeout, args.insecure)
            if a.phpinfo:
                break

    if a.reachable and not a.blocked and not args.no_probes:
        benign_probes(a, base, args.timeout, args.insecure)

    decide(a)
    if args.verify_exec:
        verify_execution(a, base, args.verify_exec, args.allow_host, args.verify_timeout)
    print(render(a))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(asdict(a), fh, indent=2, default=str)
        eprint(f"[+] JSON written to {args.json}")

    return 0 if a.verdict not in ("UNREACHABLE",) else 1


if __name__ == "__main__":
    raise SystemExit(main())
