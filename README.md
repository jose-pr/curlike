# curlike

[![Version](https://img.shields.io/pypi/v/curlike.svg)](https://pypi.org/project/curlike/)
[![Python versions](https://img.shields.io/pypi/pyversions/curlike.svg)](https://pypi.org/project/curlike/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jose-pr/curlike/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://jose-pr.github.io/curlike/)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/curlike/test.yml)](https://github.com/jose-pr/curlike/actions/workflows/test.yml)

**A `curl` that works everywhere Python does.** With a real curl on PATH,
`pycurl` runs it with your configured proxy and its credential added. Without
one, it serves the request itself: a curl-compatible command over the
standard library, with curl's exit codes and messages, checked line for line
against real curl. Documentation: <https://jose-pr.github.io/curlike/>.

## Features

- **Real curl first** — your argv and exit code go through unchanged. The
  one addition is the proxy from [httplib](https://pypi.org/project/httplib/)'s
  `HTTPLIB_PROXY`, as `--proxy` plus `--proxy-header`, which real curl would
  otherwise never read.
- **A fallback that answers as curl does** — the common surface (request,
  auth, body, output, downloads, TLS, proxies including SOCKS and https
  proxies, redirects, cookies, `-w`, `--retry`). The exit codes and messages
  are measured against curl's own builds, and the version it imitates is
  configurable.
- **Fails loud** — an option it does not implement is `curl: (2) Unsupported
  options: …`, never silently ignored.
- **Prefix gateways and URL hooks** — httplib's `prefix[:/endpoint]` proxy
  type and `HTTPLIB_HOOKS_<KEY>_CURL` wrappers work the same way here as in
  an httplib session.

## Installation

```bash
pip install curlike
```

| Extra | Adds | Needed for |
| --- | --- | --- |
| `dns` | `netimps` | `--dns-servers`, `--dns-ipv4-addr`, `--dns-ipv6-addr`, `--dns-interface`, `--doh-url`, `--interface` by name |

## Quick start

```python
from curlike.shim import main

rc = main(["-s", "-o", "page.html", "https://example.com/"])
```

## Command line

```bash
pycurl https://example.com
pycurl -s -o out.json -H 'Accept: application/json' https://api.example.com/x
python -m curlike -X POST --json '{"k":1}' https://httpbin.org/post
```

## API overview

| Module | Purpose |
| --- | --- |
| `curlike.shim` | `main()`: the drop-in curl (hooks, real curl, fallback) |
| `curlike` | `main()` / `run_fallback()`: the fallback by itself |

The other modules hold the fallback's option groups and transfer machinery
and are private.

## Settings

`<P>` is httplib's prefix (`HTTPLIB` unless `HTTPLIB_PREFIX` says otherwise).

| Variable | Sets |
| --- | --- |
| `<P>_CURL` | `0`/`no`/`off`: run the real curl exactly as typed |
| `<P>_CURL_COMPAT` | the curl version the fallback answers as (default: the real curl's, else 8.22) |
| `<P>_CURL_SSL_REVOKE` | `best-effort` (default), `true`, `false`: revocation for a Schannel curl |
| `<P>_PYTHON` | the interpreter a `.py` hook wrapper runs under |
| `<P>_PYLIB` | where to find duho when it is not installed |

## Development

```bash
dotagents pyvenv            # or any Python 3.9+ virtual environment
.pyvenv/<tag>/Scripts/python -m pip install -e ../httplib -e ".[dev]"
.pyvenv/<tag>/Scripts/python -m pytest -q
```

The parity tests compare the fallback with the real curl on PATH, and are
skipped when there is none.

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/jose-pr/curlike/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow: test gate → build
(checking the tag names the version built) → a strict docs build as a gate →
GitHub release → publish. The release workflow never deploys the docs site
itself: for a final release its last job dispatches the docs workflow at the
tag, which owns every Pages deploy.

## License

MIT — see [LICENSE](https://github.com/jose-pr/curlike/blob/main/LICENSE).
