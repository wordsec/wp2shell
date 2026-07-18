# WordSec wp2shell Checker

A single-file, dependency-free checker that tells you whether a WordPress site is
exposed to the **wp2shell** unauthenticated REST batch route-confusion vulnerability
(**CVE-2026-63030** / **CVE-2026-60137**).

It is **detection-only and non-destructive**. It sends one benign batch request and
reads public version markers. It does **not** exploit the flaw, does **not** inject
SQL, and does **not** read or modify any data on the target.

```
__        __   ___    ____    ____    _____   _____    _____
\ \  /\  / /  / _ \  |  _ \  |  _ \  / ____| | ____|  / ____|
 \ \/  \/ /  | | | | | |_) | | | | | \___ \  |  _|   | |
  \  /\  /   | |_| | |  _ <  | |_| |  ___) | | |___  | |____
   \/  \/     \___/  |_| \_\ |____/  |____/  |_____|  \_____|

  wp2shell & CVE-2026-63030 & CVE-2026-60137 | wordsec.net
```

## Affected versions

wp2shell abuses a route-confusion bug in the WordPress REST batch endpoint
(`/wp-json/batch/v1`) that allows an unauthenticated request to be dispatched under the
wrong handler. The following WordPress **core** versions are affected:

| Branch | Affected      | Fixed in |
| ------ | ------------- | -------- |
| 6.9.x  | 6.9.0 – 6.9.4 | 6.9.5    |
| 7.0.x  | 7.0.0 – 7.0.1 | 7.0.2    |

Versions ≤ 6.8.5 and ≥ 7.0.2 are not affected.

## How it works

1. **Passive version fingerprint** — reads the WordPress version from the REST API
   `generator` field and the HTML `<meta name="generator">` tag, then reports whether
   it falls in the affected range.
2. **Benign marker probe** — sends a single batch request built from empty inner
   batches. A vulnerable core answers `HTTP 207` and leaks the route-confusion marker
   pattern (`parse_path_failed`, `block_cannot_read`, `rest_batch_not_allowed`). A
   patched core, or one with the REST API disabled, does not.

No SQL injection is performed and nothing is written to the target. The verdict is
based solely on the response to the harmless probe.

## Requirements

- Python 3.7+
- No third-party dependencies (standard library only)

## Usage

```bash
python wp2shell.py https://target.example
```

| Flag              | Description                                                        |
| ----------------- | ------------------------------------------------------------------ |
| `--rest-route`    | Use `/?rest_route=/batch/v1` when `/wp-json/` is unavailable        |
| `--timeout N`     | HTTP timeout in seconds (default: 30)                              |
| `-q`, `--quiet`   | Print only the verdict, no banner                                 |

### Example output

```
[*] WordPress 6.9.3 (affected range)
[+] VULNERABLE
```

```
[-] NOT VULNERABLE
```

### Exit codes

| Code       | Meaning                              |
| ---------- | ------------------------------------ |
| `0`        | Not vulnerable                       |
| `1`        | Vulnerable                           |
| non-zero   | Target unreachable (message printed) |

Handy for monitoring your own inventory:

```bash
python wp2shell.py https://target.example -q || echo "review this host"
```

## Remediation

- Update WordPress core to **6.9.5+** or **7.0.2+**.
- If you cannot update immediately, block or restrict `/wp-json/batch/v1` (and
  `/?rest_route=/batch/v1`) at the edge / WAF.

## Legal

Run this **only** against systems you own or are explicitly authorized to test.
You are responsible for complying with all applicable laws and agreements.

## License

MIT

---

Made by [WordSec](https://wordsec.net)
