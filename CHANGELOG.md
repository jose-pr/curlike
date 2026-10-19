# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The `pycurl` console script and `python -m curlike`: the drop-in curl
  (`curlike.shim.main`). `main(argv=None, *, entry=None)` takes the
  executable acting as this curl, whose directory is skipped when looking for
  the real curl and which hook wrappers receive as `<P>_HOOK_CURL`.
- `curlike.main()`, `curlike.run_fallback()` and `curlike.shim.main()` take
  `ssl_context=` / `proxy_ssl_context=`: a caller's `ssl.SSLContext` used as
  given for every https origin or an `https://` proxy (mutual TLS, ciphers,
  protocol versions). The TLS flags it replaces are refused beside it (exit 2).
- With no proxy variable set, the system's proxy configuration routes each
  URL on the command line (through syshttp: WinHTTP, CFNetwork, libproxy, PAC,
  WPAD); its redirect hops keep that decision, as with curl's own `--proxy`.
  The real curl is handed that proxy with `--proxy` (curl reads only the
  `*_proxy` variables). `SYSHTTP_SYSTEM_PROXY=0` turns it off. Of a list
  (`PROXY a; PROXY b; DIRECT`) the first proxy that accepts a connection is
  used; with none and no DIRECT, exit 7 and real curl is not run.

### Changed

- curlike is a pure-Python curl and never runs the real one: `pycurl` and
  `python -m curlike` are `curlike.main`. The launcher that prefers the real
  curl -- hook wrappers, the agent proxy handed to curl as `--proxy`, the
  `<P>_CURL`, `<P>_CURL_SSL_REVOKE` and `<P>_PYTHON` settings -- moved to the
  dotagents net overlay (`lib/curlshim`). New for such a launcher:
  `curlike.caller_steering()`, `requested_url()`, `find_real_curl()` and
  `describe_curl()`.

### Removed

- `curlike.shim` (`main`, `default_entry`, `find_real_curl`): the dotagents
  net overlay's `lib/curlshim` is the launcher now.

- Routing comes from syshttp 0.1.0.dev6's `proxy.proxy_map()` over
  proxylib 2 (now a direct dependency): the `*_PROXY` variables are read per
  scheme, `NO_PROXY` takes CIDR entries, `HTTP_PROXY_AUTH` goes to the
  machine's proxy (a `*_PROXY` variable's or the system's) and
  `<P>_PROXY_AUTH` to `<P>_PROXY` only. Of a list the first proxy that
  answers is used; a lone proxy is not probed. The exit-7 message is
  `no proxy of the list is reachable: host:port, ...`.

- The package stands alone. It was previously the dotagents `net` overlay's
  curl shim (`bin/curl.py`) and its fallback (`httplib.cli`,
  `python -m httplib`). The fallback is now `curlike` (`curlike.main`), and
  the shim is `curlike.shim`. It runs on syshttp, the overlay's `httplib`
  as a package of its own.
- Settings follow syshttp's prefix (`SYSHTTP_PREFIX`, default `SYSHTTP`):
  `NET_CURL` → `SYSHTTP_CURL`, `NET_CURL_COMPAT` → `SYSHTTP_CURL_COMPAT`,
  `NET_CURL_SSL_REVOKE` → `SYSHTTP_CURL_SSL_REVOKE`, `AGENTS_PYTHON` →
  `SYSHTTP_PYTHON`, `AGENTS_PYLIB` → `SYSHTTP_PYLIB`. The proxy and hook
  variables are syshttp's (`SYSHTTP_PROXY`, `SYSHTTP_HOOKS_<KEY>_CURL`). With
  `SYSHTTP_PREFIX=AGENTS`, the `AGENTS_*` names are read instead.
- The fallback's TLS is the system's by default (syshttp's sslcontext system
  context): the operating system verifies certificates on Python 3.10+, and a
  server that asks for a client certificate gets one from the OS store, chosen
  as a browser chooses. `--cert` turns the store off: the named certificate is
  the one sent. `--crlfile` keeps an OpenSSL
  context, because the OS verifier ignores CRL flags.
- A malformed proxy setting is reported as `curl: ignoring the configured
  proxy: …` (was `ignoring the agent proxy`).
- `curl -V` from the fallback says `curl 0.0.0-curlike-shim … -- curlike
  fallback`, and `%{json}`'s `curl_version` says `(curlike fallback)`.

### Fixed

- `-k`, `--proxy-insecure` and `--doh-insecure` build a plain `ssl` context. The OS verifier
  (truststore) on macOS still evaluated the chain under them and failed with 60.
- `--local-port` with a range moves to the next port when `connect()` finds
  the port in use. Windows reports a port whose last connection to the same
  address is in TIME_WAIT there, not at `bind()`, and the fallback used to
  give up with exit 7.

[Unreleased]: https://github.com/jose-pr/curlike/commits/main
