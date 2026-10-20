# curlike

[![Version](https://img.shields.io/pypi/v/curlike.svg)](https://pypi.org/project/curlike/)
[![Python versions](https://img.shields.io/pypi/pyversions/curlike.svg)](https://pypi.org/project/curlike/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jose-pr/curlike/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://jose-pr.github.io/curlike/)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/curlike/test.yml)](https://github.com/jose-pr/curlike/actions/workflows/test.yml)

**A `curl` that works everywhere Python does.** `pycurl` is a
curl-compatible command in pure Python, over the standard library, with
curl's exit codes and messages, checked line for line against real curl; and
`curlike` is the library behind it. It never runs the real curl.
Documentation: <https://jose-pr.github.io/curlike/>.

## Features

- **Answers as curl does** — the common surface (request,
  auth, body, output, downloads, TLS, proxies including SOCKS and https
  proxies, redirects, cookies, `-w`, `--retry`). The exit codes and messages
  are measured against curl's own builds, and the version it imitates is
  configurable.
- **Fails loud** — an option it does not implement is `curl: (2) Unsupported
  options: …`, never silently ignored.
- **Your own TLS context** — from Python, `curlike.main(argv, ssl_context=...)`
  runs the curl command line over a context you built: mutual TLS with a
  keystore identity, a cipher list, a pinned protocol version.
- **The system's proxy** — [syshttp](https://github.com/jose-pr/syshttp)
  routes it: `SYSHTTP_PROXY`, the `*_PROXY` variables, else the system's
  configuration for the URL (PAC and WPAD included), its `prefix[:/endpoint]`
  gateways included.

## Installation

```bash
pip install curlike
```

| Extra | Adds | Needed for |
| --- | --- | --- |
| `dns` | `netimps` | `--dns-servers`, `--dns-ipv4-addr`, `--dns-ipv6-addr`, `--dns-interface`, `--doh-url`, `--interface` by name |

## Quick start

```python
import curlike

rc = curlike.main(["-s", "-o", "page.html", "https://example.com/"])
```

Mutual TLS with a context of your own:

```python
import ssl
import curlike

ctx = ssl.create_default_context()
ctx.load_cert_chain("client.pem", "client.key")
rc = curlike.main(["-s", "https://mtls.example/"], ssl_context=ctx)
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
| `curlike` | `main()` / `run_fallback()`: the command; `caller_steering()`, `requested_url()`, `find_real_curl()`, `describe_curl()` for a launcher |

The other modules hold the command's option groups and transfer machinery
and are private.

## Settings

`<P>` is syshttp's prefix (`SYSHTTP` unless `SYSHTTP_PREFIX` says otherwise).

| Variable | Sets |
| --- | --- |
| `<P>_PYTHON` | the interpreter a `.py` hook wrapper runs under |
| `<P>_PYLIB` | where to find duho when it is not installed: for a host tool that runs curlike from a zipapp (`.pyz`) or a vendored directory |

## Development

```bash
dotagents pyvenv            # or any Python 3.9+ virtual environment
.pyvenv/<tag>/Scripts/python -m pip install -e ../syshttp -e ".[dev]"
.pyvenv/<tag>/Scripts/python -m pytest -q
```

The parity tests compare curlike with the real curl on PATH, and are
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
