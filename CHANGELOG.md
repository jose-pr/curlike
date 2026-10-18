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

### Changed

- The package stands alone. It was previously the dotagents `net` overlay's
  curl shim (`bin/curl.py`) and its fallback (`httplib.cli`,
  `python -m httplib`). The fallback is now `curlike` (`curlike.main`), and
  the shim is `curlike.shim`.
- Settings follow httplib's prefix (`HTTPLIB_PREFIX`, default `HTTPLIB`):
  `NET_CURL` → `HTTPLIB_CURL`, `NET_CURL_COMPAT` → `HTTPLIB_CURL_COMPAT`,
  `NET_CURL_SSL_REVOKE` → `HTTPLIB_CURL_SSL_REVOKE`, `AGENTS_PYTHON` →
  `HTTPLIB_PYTHON`, `AGENTS_PYLIB` → `HTTPLIB_PYLIB`. The proxy and hook
  variables are httplib's (`HTTPLIB_PROXY`, `HTTPLIB_HOOKS_<KEY>_CURL`). With
  `HTTPLIB_PREFIX=AGENTS`, the `AGENTS_*` names are read instead.
- A malformed proxy setting is reported as `curl: ignoring the configured
  proxy: …` (was `ignoring the agent proxy`).
- `curl -V` from the fallback says `curl 0.0.0-curlike-shim … -- curlike
  fallback`, and `%{json}`'s `curl_version` says `(curlike fallback)`.

[Unreleased]: https://github.com/jose-pr/curlike/commits/main
