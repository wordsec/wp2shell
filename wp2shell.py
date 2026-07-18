#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

BANNER = r"""
__        __   ___    ____    ____    _____   _____    _____
\ \  /\  / /  / _ \  |  _ \  |  _ \  / ____| | ____|  / ____|
 \ \/  \/ /  | | | | | |_) | | | | | \___ \  |  _|   | |
  \  /\  /   | |_| | |  _ <  | |_| |  ___) | | |___  | |____
   \/  \/     \___/  |_| \_\ |____/  |____/  |_____|  \_____|

  wp2shell & CVE-2026-63030 & CVE-2026-60137 | wordsec.net
"""

MARKER_CODES = ("parse_path_failed", "block_cannot_read", "rest_batch_not_allowed")
DESYNC_PRIMER = {"method": "POST", "path": "///"}
VERSION_RE = re.compile(r"([0-9]+(?:\.[0-9]+){1,3})")
USER_AGENT = "wordsec.net"


def enable_color() -> bool:
    if not sys.stdout.isatty():
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


COLOR = enable_color()


def paint(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if COLOR else text


def request(url: str, timeout: float, payload=None):
    headers = {"User-Agent": USER_AGENT}
    data = None
    method = "GET"
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode()
        method = "POST"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except OSError as exc:
        reason = getattr(exc, "reason", exc)
        raise SystemExit(paint("31", f"[-] cannot reach {url}: {reason}"))


def endpoint(base: str, rest_route: bool) -> str:
    base = base.rstrip("/")
    return f"{base}/?rest_route=/batch/v1" if rest_route else f"{base}/wp-json/batch/v1"


def found_markers(body: str) -> set:
    try:
        parsed = json.loads(body)
    except ValueError:
        return set()
    found = set()

    def walk(value) -> None:
        if isinstance(value, dict):
            code = value.get("code")
            if code in MARKER_CODES:
                found.add(code)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(parsed)
    return found


def is_affected(version: str) -> bool:
    parts = [int(p) for p in version.split(".")[:3]]
    while len(parts) < 3:
        parts.append(0)
    parsed = tuple(parts)
    return (6, 9, 0) <= parsed <= (6, 9, 4) or (7, 0, 0) <= parsed <= (7, 0, 1)


def detect_version(base: str, timeout: float) -> str | None:
    base = base.rstrip("/")
    for path in ("/wp-json/", "/?rest_route=/"):
        status, body = request(base + path, timeout)
        if status >= 400:
            continue
        try:
            generator = json.loads(body).get("generator", "")
        except ValueError:
            generator = ""
        match = VERSION_RE.search(generator)
        if match:
            return match.group(1)
    status, body = request(base + "/", timeout)
    if status < 400:
        match = re.search(r'name=["\']generator["\'][^>]*content=["\']WordPress\s+([0-9.]+)', body, re.I)
        if match:
            return match.group(1)
    return None


def probe(base: str, rest_route: bool, timeout: float):
    return request(
        endpoint(base, rest_route),
        timeout,
        payload={
            "requests": [
                DESYNC_PRIMER,
                {"method": "POST", "path": "/wp/v2/posts"},
                {"method": "POST", "path": "/wp/v2/block-renderer/core/archives"},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        },
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="WordSec wp2shell vulnerability checker (wordsec.net)")
    parser.add_argument("url", help="target base URL, e.g. https://target")
    parser.add_argument("--rest-route", action="store_true", help="use /?rest_route=/batch/v1")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("-q", "--quiet", action="store_true", help="print only the verdict")
    args = parser.parse_args(argv)

    if not args.quiet:
        print(paint("36", BANNER))

    version = detect_version(args.url, args.timeout)
    if version and not args.quiet:
        tag = "affected range" if is_affected(version) else "not in affected range"
        print(f"[*] WordPress {version} ({tag})")

    status, body = probe(args.url, args.rest_route, args.timeout)
    vulnerable = status == 207 and all(code in found_markers(body) for code in MARKER_CODES)

    if vulnerable:
        print(paint("31", "[+] VULNERABLE"))
        return 1
    print(paint("32", "[-] NOT VULNERABLE"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
