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

- CI installs syshttp at one pinned commit (the 0.1.0.dev7 floor) in every
  workflow, so a run is reproducible and the floors job tests the floor.

- There is no hidden 30 s time limit: --connect-timeout bounds the connect
  only, -m is a deadline for the whole attempt (redirect hops and a trickling
  body included), and --timeout (not a curl option) is opt-in. -N is real, and
  the "Output written to FILE" line, which curl never prints, is gone.

- The default request is curl's: User-Agent: curl/8.22.0 and Accept: */*, and
  no Accept-Encoding: identity. Connection: close remains, the one difference,
  because each transfer is one request on one connection.

- Two URLs, an unknown option and a missing option value are curl-style one-
  line usage errors (exit 2, with the --help hint) instead of argparse's
  52-line usage dump.

- The duho floor is 0.7.0, the first release with duho.Meta (the suite passes
  at it); -v is documented as printing the request as given, the caller's
  Authorization and Cookie included, with only the configured proxy's
  credential redacted.

- The test run is warning-clean: the fake servers close the connections they
  open, and the test configuration turns every warning, ResourceWarning
  included, into an error.

### Removed

- `<P>_CURL_COMPAT` and the per-version answers behind it (`curlike.compat`):
  curlike answers as curl 8.22, the latest stable release, and follows new
  releases. `find_real_curl()` and `describe_curl()` are unchanged.
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

- -L follows redirects in curlike's own loop, as curl does: 50 hops by default
  (--max-redirs -1 is unlimited, 0 refuses the first; exit 47 past the limit);
  a redirect to ftp:// is exit 1 instead of a direct connection outside the
  proxy and every connection option, and file:// or gopher:// are exit 1; a -H
  Host goes only to the first request's host; -D and -i show every hop's
  headers; -e 'URL;auto' sets each hop's Referer to the page it came from;
  --location-trusted implies -L.

- With the cookie engine (-b FILE or -c), the cookies a redirect hop sets are
  sent to the next hop and filed under that hop's host, not the first URL's.

- --digest and --anyauth answer a server's 401 once, with one implementation
  shared with the proxy's: a rejected password is sent once (two requests, not
  seven) and the 401 and its body are the response; a challenge curlike cannot
  answer (Negotiate, Bearer) is the response too, not exit 2;
  algorithm=SHA-256 works on Python 3.9; quotes in the user name or realm are
  escaped.

- The netrc is read as curl reads it: quoted words with backslash escapes,
  comments, a machine name in any case, the first matching entry in file
  order, a login with no password (an empty one, not None), and the login a
  user@ URL names. -u USER asks for the password, as curl does.

- -c no longer stores a cookie whose Domain the host that set it does not
  domain-match, or a public suffix, and a cookie with no Path gets the
  directory of the request (RFC 6265, through syshttp 0.1.0.dev14, now the
  floor).

- The body is streamed, not held in memory (a 200 MB download peaks near 40
  MB, not 470 MB, and the first byte reaches stdout at once): --max-filesize
  stops a body of unknown length at the cap, --compressed decodes piece by
  piece, and -T reads its file as it sends it.

- Response limits are curl's: headers over 300 KB are exit 56, over 5000
  headers exit 100, a conflicting or negative Content-Length or a NUL in a
  header exit 8. http.client's limits and socket.getaddrinfo are no longer
  replaced for the length of a transfer (concurrent calls cannot leave them
  changed).

- A 206 answering -C must start at the resume offset or it is exit 33 (the
  file is left alone), and --remove-on-error removes a file the failed
  transfer overwrote; with -C it is exit 2, as in curl.

- --retry covers a name that does not resolve and, under --retry-all-errors, a
  body cut short; every failed attempt prints its error line; the warning
  reads "Retrying in N seconds" (curl 8.21); a Retry-After of 0 is none, and
  one past --retry-max-time ends the retries with curl's warning.

- --crlfile loads only the CRLs of its file: a CA certificate inside it is no
  longer trusted (a file with no CRL is exit 82). The contexts curlike builds
  no longer apply Python 3.13's strict X.509 checks, so a leaf with no
  Authority Key Identifier verifies as it does with curl and on older Pythons.

- --proxy-pinnedpubkey is checked on a proxy connection reopened after a 407,
  and --pinnedpubkey, -0, --interface, --local-port and the -w timings apply
  over --unix-socket (it now goes through the one connector); a CONNECT
  carries a single Host line on Python 3.12+; an over-long SOCKS5 user name,
  password or host name is exit 97; an unreadable --pinnedpubkey file no
  longer fails an http:// transfer; --doh-url with an unusable --cacert fails
  the lookup (77) instead of falling back to the OS store.

- -H sends a repeated name once per value, replaces only a default of the same
  name, and -H 'Name:' removes Host, Connection, Accept-Encoding and Content-
  Type too, as the header always claimed. Header values go out as UTF-8 (they
  were refused or sent as latin-1), and response header bytes are written back
  unchanged by -i, -D and -w, with the status line's HTTP version; -w @file is
  read and written as bytes. A URL with a space or control character is exit 3
  (not 8) and nothing is sent; non-ASCII characters in a URL are sent percent-
  encoded as UTF-8 (a host as IDNA) instead of exit 2.

- -J reads filename= only at a parameter's start and gives a Windows name as
  curl does (no drive-relative C:evil out of --output-dir, no device names);
  -O with no name in the URL writes the last segment or curl_response (exit 23
  before); a -c jar that cannot be written no longer ends in a traceback;
  --etag-save is created before the transfer (26 when it cannot be); -b is a
  file when it has no = (a missing one holds nothing, - is stdin) and -c -
  writes the jar to stdout; -d @file also drops NUL and an unreadable data, -H
  or -w file is curl's three lines; --data-urlencode and --url-query write a
  space as +; -d x --json y joins with no &; -F takes @"file;name" and
  type=...;charset=..., and no longer types .json as application/json; -T
  sends no Content-Type and adds no file name to a URL with a query; -I -X
  POST sends POST; %{json} writes "" for the addresses of a transfer that
  never connected; the connect failure reads host:port.

- Messages follow curl 8.21's words where they had drifted: a bad chunk names
  the byte (0x7a), a bad gzip stream drops zlib's prefix, a refused proxy
  connection says "over proxy", a missing --cacert, --crlfile, --netrc-file or
  --proxy-cacert file is wrapped and followed by the option hint, an
  unreadable -d, -H or -w file wraps its path, a -T file that is not there
  prints curl's three lines, an unknown --proto name prints no first line, a
  proxy with no scheme is shown as http://..., and the glob error words match.

