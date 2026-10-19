# `curlike` — public API header

Header-file-style reference for the `curlike` package: every public export with
its signature, arguments, contract and gotchas, so the package can be used
without reading its source. It ships inside the package and is
self-contained. Development documentation lives with the source at
<https://github.com/jose-pr/curlike>.


A curl-compatible command over the standard library, and the library
behind it. It never runs the real curl: a launcher that prefers the real one
(the dotagents net overlay's `curl`) decides that, with the helpers below.
The command is the API. The importable names are in `curlike` itself; every
other module holds the option groups and transfer machinery: none of them is
public, and their import paths may move.

`pip install curlike` brings `syshttp` (proxy, cookies, TLS and URL hooks)
and `duho` (the command's options). The extra `dns` adds `netimps` for
`--dns-servers`, `--dns-ipv4-addr`, `--dns-ipv6-addr`, `--dns-interface`,
`--doh-url` and `--interface` by name. Without it those flags are refused
with exit 2.

## Entry points

```python
curlike.main(argv=None, *, ssl_context=None, proxy_ssl_context=None) -> int
curlike.run_fallback(argv, *, ssl_context=None, proxy_ssl_context=None) -> int  # raises instead of printing
curlike.caller_steering(argv: list[str]) -> tuple[str | None, str | None, str | None]
curlike.requested_url(argv: list[str]) -> str | None
curlike.find_real_curl(skip: str | os.PathLike | None = None) -> str | None
curlike.describe_curl(path: str) -> tuple[tuple[int, ...] | None, bool]
```

- `main` runs a curl command line: one-line `curl: (N) …` errors and curl's
  exit codes. `run_fallback` raises `NotImplementedError` (an
  unsupported flag), `ValueError` (a conflict or a bad proxy setting) and
  `SystemExit` (usage, `--help`).
- `ssl_context` is a caller's `ssl.SSLContext`, used as given for every
  https origin: its trust store, `verify_mode`, client identity (mutual TLS,
  including a key held in an OS keystore), ciphers and protocol versions
  decide. `proxy_ssl_context` does the same for an `https://` proxy. A flag
  the context replaces, given beside it, is exit 2 (`curl: (2) ssl_context
  replaces --cacert: give one or the other`). For the origin those flags are
  `-k`, `--cacert`, `--capath`, `--cert`, `--key`, `--pass`, `--ciphers`,
  `--crlfile`, `--tlsv1*` and `--tls-max`; the proxy has their `--proxy-*`
  twins. `--pinnedpubkey` still applies. A context that is not an
  `ssl.SSLContext` raises `TypeError`.
- `caller_steering(argv)` is `(proxy, noproxy, proxy_user)` as argv names them
  (`-x`/`--proxy`, `--noproxy`, `-U`/`--proxy-user`), `None` each when
  absent; `requested_url(argv)` the URL asked for (`--url`, else the first
  positional), curl's default scheme applied, or `None`. Both read argv the
  way curl does (combined short flags, option values that look like
  options) without running anything.
- `find_real_curl(skip)` is the system curl on PATH, or `None`: PATH walked
  directory by directory, skipping the directory `skip`, any hit outside the
  directory searched and any hit with a `curl.py` beside it (a launcher of
  curlike). `describe_curl(path)` is that curl's version (`None` when it does
  not answer `-V`) and whether it is built on Windows' Schannel.

## Command line

```bash
pycurl [curl options] URL...            # the console script: curlike.main
python -m curlike [curl options] URL...
```

Neither runs the real curl. A launcher named `curl` that prefers the real one
when it is installed is the dotagents net overlay's (`lib/curlshim`).

## Behaviour

`<P>` is syshttp's settings prefix: `SYSHTTP` unless `SYSHTTP_PREFIX` names
another. The proxy settings (`<P>_PROXY`, `<P>_PROXY_AUTH`,
`<P>_PROXY_AUTH_HEADER`, `<P>_PROXY_TYPE`) are syshttp's. Its own API header
documents them.

    curl https://example.com
    curl -s -o out.json -H 'Accept: application/json' https://api.example.com/x
    curl -X POST -d '{"k":1}' -H 'Content-Type: application/json' https://h/api

- **The proxy is syshttp's**: `<P>_PROXY` (credential and type as syshttp
  documents them), then the request scheme's `*_PROXY` variable, then the
  system's configuration for each URL on the command line (WinHTTP,
  CFNetwork, libproxy, PAC, WPAD; `<P>_SYSTEM_PROXY=0` turns it off; with
  `HTTP_PROXY_AUTH` as its header). Of a list the first proxy that accepts a
  connection is used; when none does and the list holds no DIRECT, exit 7
  (`curl: (7) no proxy of the list is reachable: …`); a lone proxy is not
  probed. **Every redirect hop** is decided again (proxied, or direct without
  the credential for a `NO_PROXY` host); loopback is proxied unless listed, as
  in curl. A `prefix` gateway is spoken per hop. `-x` names a proxy of your
  own (always `connect`, never given the configured credential); `--noproxy`
  (`*` or a host list) replaces `NO_PROXY`, as in curl; `-U` replaces the
  credential. A malformed `<P>_PROXY`/`<P>_PROXY_TYPE` that would be used is
  exit 2.
- Supported (`curl -h` lists them): request `-X -G --url --url-query -H -A -e
  -r --compressed --request-target --proto --proto-redir --proto-default --path-as-is`; auth `-u --basic --digest --anyauth --oauth2-bearer -n --netrc-file
  --netrc-optional` and `user:pw@` in the URL; body `-d --data-ascii --data-raw
  --data-binary --data-urlencode --json -F --form-string -T`; output `-o -O
  --remote-name-all --output-dir --create-dirs -D -i --show-headers -I -s -S -v
  -f --fail-with-body -w --stderr`; downloads `-C -J -R -z --etag-save
  --etag-compare --no-clobber --skip-existing --remove-on-error --max-filesize`;
  TLS `-k --cacert --capath -E/--cert --cert-type --key --key-type --pass
  -1/--tlsv1 --tlsv1.0 --tlsv1.1 --tlsv1.2 --tlsv1.3 --tls-max --ciphers --crlfile
  --pinnedpubkey`; connection `-x -U -p -0/--http1.0 --proxy-header --proxy-basic --socks4
  --socks4a --socks5 --socks5-hostname --socks5-basic --preproxy --proxy-insecure --proxy-cacert
  --proxy-capath --proxy-cert --proxy-cert-type --proxy-key --proxy-key-type --proxy-pass --proxy-ciphers
  --proxy-crlfile --proxy-pinnedpubkey --proxy-tlsv1 --proxy-digest --proxy-anyauth --noproxy -L
  --max-redirs --location-trusted
  --post301 --post302 --post303 -m --connect-timeout --timeout -4 -6 --resolve
  --connect-to --unix-socket --interface --local-port --limit-rate -Y/--speed-limit
  -y/--speed-time --ignore-content-length --dns-servers --dns-ipv4-addr --dns-ipv6-addr
  --dns-interface --doh-url --doh-insecure --retry --retry-delay --retry-max-time
  --retry-connrefused --retry-all-errors`; cookies `-b -c -j`; and the no-ops `-q -g --fail-early --expect100-timeout
  --tcp-fastopen --false-start --happy-eyeballs-timeout-ms --random-file --egd-file
  --http1.1 -N -# --no-progress-meter --styled-output --no-keepalive
  --keepalive-time --tcp-nodelay --ssl-no-revoke --ssl-revoke-best-effort
  --ca-native --proxy-ca-native --no-alpn --no-npn --no-sessionid`, each true of
  this client (no config file read, no progress shown, no keepalive, session
  reuse or ALPN, and no revocation check but `--crlfile`'s). `-g` sends a URL's `{}` / `[]` as typed;
  without it a glob pattern (one transfer per expansion in curl) is refused,
  exit 2, and a broken one is curl's exit 3. A URL with no scheme is
  `http://`, as in curl; an option value may start with `-` (`-z -DATE`, `-d
  -1`), as in curl. With curl's meaning where it matters:
  - **`-L` follows as curl does**, in its own loop: at most 50 redirects
    (`--max-redirs N`; `-1` unlimited, `0` refuses the first), then exit 47;
    credentials (`Authorization` from `-u`, `--oauth2-bearer` or `-H`;
    `Cookie` from `-H` or a `-b` string) go to a hop only while its scheme,
    host and port are the first request's, unless `--location-trusted` (which
    also implies `-L`), and a `-H 'Host:'` only to the first request's host;
    the cookie engine (`-b FILE`, `-c`) keeps what each hop sets and sends it
    to the next hop it applies to, and `-c` files a cookie under the host of
    the hop that set it; `-D` and `-i` show every hop's headers; `-e
    'URL;auto'` sets each later hop's Referer to the page it came from;
    301/302 turn a POST into a GET (`--post301`/`--post302` keep it), 303
    anything but HEAD, 307/308 keep method and body, and `-X` stays forced. A
    redirect to a scheme this command cannot fetch (`ftp://`, `ftps://`) is
    exit 1 (`Protocol "ftp" not supported or disabled in libcurl`); one that
    `--proto-redir` forbids (`file://`, `gopher://` by default) is exit 1
    too.
  - **Credentials**: `-u` wins, then `user:pw@` in the URL, then the netrc entry
    for the host (`default` if none matches) with `-n`/`--netrc-optional`;
    `--digest` answers the server's challenge. `-n` without a netrc is exit 26.
  - **Downloads**: `-C -` resumes from the file's size (a server ignoring the
    range is exit 33, a 416 means already complete); `-J` takes the
    `Content-Disposition` name without its directories and never overwrites
    (exit 23); `-R` sets the mtime from `Last-Modified`; `-z DATE|FILE` (`-z
    -DATE`: unmodified since) and `--etag-compare` make the request conditional,
    and an unmet condition or a 304 writes no file; `--no-clobber` writes
    `name.1`..`name.100`; `--max-filesize` over the limit is exit 63 with nothing
    written.
  - **Proxies**: `-x` takes `http://` and `socks4://` / `socks4a://` /
    `socks5://` / `socks5h://` (`socks://` is SOCKS4), as does
    `<P>_PROXY`; the `--socks*` flags name one too and override `-x`.
    `socks5` and `socks4` resolve the name here, `socks5h` and `socks4a` let
    the proxy do it; SOCKS5 credentials come from `-U` or the URL. A SOCKS
    handshake that fails is exit 97 (refused, unreachable, rejected
    credentials, no acceptable method, dropped). `--preproxy socks5h://...`
    reaches the `-x` proxy through SOCKS. `--proxy-header` goes to the proxy
    only: the request to it, or the CONNECT -- never through a tunnel, never
    to a bypassed host. `--proxy-basic` is a no-op (`-U` is Basic). An
    `https://` proxy is spoken to over TLS, verified by its own options --
    `--proxy-cacert`, `--proxy-capath`, `--proxy-insecure`, `--proxy-cert` /
    `--proxy-key` / `--proxy-pass`, `--proxy-crlfile`,
    `--proxy-pinnedpubkey`, `--proxy-ciphers`, `--proxy-tlsv1` -- never by
    `--cacert` or `-k`, which stay the origin's; an https target goes through
    it with the origin's TLS inside the proxy's. `--proxy-digest` sends no credential up front and
    answers the proxy's 407 once with Digest (MD5 / SHA-256), on the plain
    request or on the CONNECT; `--proxy-anyauth` takes Digest when offered, else
    Basic. NTLM, Negotiate and SOCKS5 GSS-API are not available (no standard-
    library implementation): those flags stay refused.
  - **URLs as curl reads them**: `/a/../b` is sent as `/b` and `/a/./b/.` as
    `/a/b/` (the query untouched), unless `--path-as-is`; a redirect's target
    too. `--proto` (`+name`, `-name`, `=name`, `all`) limits every request and
    hop, `--proto-redir` (default http, https, ftp, ftps) the redirects: a
    disallowed one is exit 1. `--proto-default https` is the scheme of a URL
    that names none. `-b <file>` sends its cookies in curl's order (longest
    path, domain, name first; the later line first); `-j` leaves out its
    session cookies. `-i` / `-D` show a proxy's CONNECT reply before the
    response, as curl does, unless `--suppress-connect-headers`.
  - **Shaping a connection**: `--interface` takes an IP address, a host
    (`host!NAME`) or an interface (`if!NAME`, or a bare name; by name only with
    netimps installed), `--local-port N[-M]` the first port of the range that
    binds (none: exit 45). `-p` tunnels an `http://` URL through the proxy with
    CONNECT too. `--limit-rate RATE[k|m|g]` paces the body both ways;
    `--speed-limit`/`--speed-time` (30 s, 1 B/s when only one is given) end a
    slower transfer with exit 28. `--anyauth` sends no credentials until the
    server's 401 says which (Digest, else Basic). `--request-target` replaces
    the first request's target (`*` for `OPTIONS`). `--crlfile` checks the
    server's chain against a PEM list (revoked: 60); `--pinnedpubkey
    sha256//BASE64[;...]` or a public-key file requires the server's key (exit
    90), checked even with `-k`.
  - **Name resolution by netimps** (`pip install 'netimps>=0.4.1'`; without it,
    or with an older one, these flags are refused, exit 2): `--dns-servers IP[:PORT],...` asks those
    nameservers (UDP, TCP when truncated), `--dns-ipv4-addr` /
    `--dns-ipv6-addr` / `--dns-interface` send the queries from that address,
    `--doh-url https://...` asks a DNS-over-HTTPS endpoint, verified as the
    transfer is (`--cacert`) unless `--doh-insecure`, and never through a
    proxy. A name none of them resolves is exit 6; an address needs no lookup.
    `--doh-url` is checked against real curl; the `--dns-servers` family needs a
    curl built with c-ares, which most are not (they refuse it, exit 2).
  - **Connections**: `-4`/`-6`, `--resolve HOST:PORT:ADDR` and `--connect-to
    HOST1:PORT1:HOST2:PORT2` steer only name resolution, so the `Host` header,
    TLS name and certificate check stay the URL's; `--unix-socket PATH` needs a
    Python with `AF_UNIX` (not Windows CPython), else it is refused.
  - **Exit codes are curl's**, checked against real curl by the
    project's parity tests (same command, same fake servers; skipped
    without a curl). An HTTP status is a response, printed and exit 0 (a 404, a
    302 without `-L`, a plain-http proxy's 407); `-f` makes a 4xx/5xx exit 22
    with no body, `--fail-with-body` the same exit with the body.
    Before anything is sent: 1 a scheme curl does not speak, 3 a URL it cannot
    parse; 2 a `--cacert` / `--netrc-file` naming no file (from curl 8.18 on;
    before, 77 at the handshake / 26), 26 a `-d @` / `-H @`
    / `-w @` / `-T` file that cannot be read (these print `curl: message`
    with no `(N)` and no `-w`, as curl does). Connecting: 5 the proxy's name
    or URL is unusable, 6 the host's name, 7 could not connect, 28 timed out,
    35 a failed TLS handshake, 60 a certificate that does not verify, 58 a
    client certificate and 77 a CA bundle/path that cannot be loaded (at the
    handshake, so an `http://` transfer never fails on them), 59 an unusable
    `--ciphers` list. A proxy refusing the https CONNECT is 7 (22 under `-f`),
    dropping it 56. The reply: 52
    nothing came back, 1 not HTTP at all, 56 the connection reset, 18 a body
    shorter than its `Content-Length` or chunks cut short (what arrived is
    written first), 56 a malformed chunk; 23 when `-o`/`-D`/`-O` cannot be
    written, 26 when a `-F` file cannot be read. An unsupported flag, a
    conflicting pair (`-d` with `-F`, `-f` with `--fail-with-body`) or a bad
    proxy configuration is exit 2 (`curl: (2) …`, one line, never a
    traceback). `-o /dev/null` is the null device on Windows too.
  - **`--retry N`** retries what curl calls transient — a timeout and HTTP
    408/429/500/502/503/504 (`syshttp.retry.TRANSIENT_STATUSES`, the list the
    requests session retries too) — after 1s, doubling (`--retry-delay` fixes
    it, a `Retry-After` wins), within `--retry-max-time`; `--retry-connrefused`
    adds a refused connection, `--retry-all-errors` any error (with `-f`, an
    HTTP error status too). Each retry warns on stderr unless `-s`.
  - `--json` sends `Content-Type` and `Accept: application/json` (repeats
    concatenate); `--data-urlencode` takes curl's `content`, `=content`,
    `name=content`, `@file`, `name@file`; `-G` moves the data into the query;
    `--url-query` adds to it (`+` as it stands). `-F name=value`,
    `name=@file` (an upload: filename, type by extension), `name=<file` (its
    content), with `;type=` / `;filename=`. `-T file` PUTs it (a URL ending in
    `/` gets its name). `-r` is `Range: bytes=…`, `--oauth2-bearer` a Bearer
    `Authorization`.
  - **`-w` / `--write-out`** (`@file`, `@-` read the format) writes curl's
    output for `http_code response_code http_version method scheme url
    url_effective redirect_url num_redirects content_type num_headers
    header_json size_download size_upload time_total time_starttransfer
    exitcode errormsg filename_effective urlnum`, the timings `time_namelookup
    time_connect time_appconnect time_pretransfer time_posttransfer
    time_redirect time_queue`, the addresses `remote_ip remote_port local_ip
    local_port`, `num_connects num_retries speed_download speed_upload
    size_header size_request size_delivered http_connect proxy_used referer
    conn_id xfer_id`, the parts `url.*` / `urle.*` (scheme, user, password,
    host, port, path, query, fragment), and `%{json}` with curl's keys, plus
    `%header{name}`, `%{stdout}` / `%{stderr}` / `%{onerror}`, `%%` and `\n
    \r \t` — after failures too (`000` and exit 7 when nothing answered, the
    status after `-f`'s 22). Timings are measured on the connection (lookup,
    connect, handshake, request sent, first byte); urllib opens a new
    connection per redirect, so `num_connects` counts hops curl may reuse one
    for. In
    `%{json}`, `ssl_verify_result` is 0 (verified, or not checked under
    `-k`); `certs` / `num_certs` are empty. Any other variable (`certs`,
    `ssl_verify_result`, …) is refused before the request is sent. `-q` is a
    no-op (no `.curlrc` is read).
  - `-d` repeats and joins with `&`; `@file` reads a file (CR/LF stripped, as
    curl does), `@-` stdin; `--data-binary` keeps bytes as they are; a body
    without a `Content-Type` gets `application/x-www-form-urlencoded`.
  - `-H 'Name: v'` sets, `-H 'Name:'` removes the header (urllib's own defaults
    included), `-H 'Name;'` sends it empty, `-H @file` one header per line. `-u user:pass` is Basic, `-e` the
    Referer, `--compressed` asks for gzip/deflate and decodes the body.
  - `-b <file>` sends only the rows that apply to the URL — domain (the leading
    dot or the `TRUE` flag covers subdomains), path, `Secure` only over https,
    not expired, `#HttpOnly_` rows included — so a jar with several hosts never
    leaks one host's cookies to another. `-c` writes the origin's cookies with
    their expiry and `HttpOnly`, on top of what `-b` read.
  - `-I` prints the headers by itself; `-i` adds them to a body.
  - **An output that cannot be written** is exit 23 in curl's words, which
    depend on where the write failed, and `%{errormsg}` follows them. A stdout
    whose reader went away (`curl … | head -c 16`): `Failure writing output to
    destination, passed N returned M` when the write overflowed the 4096 bytes
    the C library holds for a pipe, `Failed writing body` (no code on that
    line) when it failed only at the final flush. `-o` naming what cannot be
    opened: `client returned ERROR on write of N bytes`. `-D` likewise: `Failed
    to open <path>`; `-D -` to a dead stdout: `Failed writing headers to -`.
    Lines without a code are wrapped at the terminal's width (79 with none),
    as curl wraps them. What `-w` would then have written to stdout is dropped;
    when only `-w` had stdout (the body went to `-o`), the exit code stays the
    transfer's.
- **Unsupported flags fail loud** (`curl: (2) Unsupported options: --http2`, exit
  2) rather than silently do the wrong thing — that guard is deliberate. If you
  hit one, call real `curl`.
- **Revocation**: curlike checks no certificate revocation (as an OpenSSL
  curl) unless `--crlfile`.
- **One curl** — curlike answers as curl 8.22, the latest stable release it
  was measured against, and follows new releases; it does not imitate older
  ones, whose exit codes, messages and `-w` variables differ in places.
- TLS is the **system's** — `syshttp.tls` (sslcontext's system
  context: the OS verifies servers on Python 3.10+, CryptoAPI or the Security
  framework), the same the requests session uses; a server that asks for a
  client certificate gets one from the OS store (smart cards included), chosen
  as a browser chooses, unless `--cert` names one; `--crlfile` keeps an OpenSSL context
  over the system store, since the OS verifier ignores CRL flags — unless `--cacert` / `--capath` or
  `$CURL_CA_BUNDLE` name one, which replaces it as in curl; `-k/--insecure`
  disables verification. `--cert file[:password]` (the file may hold the key),
  `--key`, `--pass` present a client certificate, PEM only.
- `-v` prints the proxy with the password redacted; nothing here logs a credential.

## Environment variables

| Variable | Sets | Default |
| --- | --- | --- |
| `<P>_PYLIB` | paths (`os.pathsep`-separated) to find duho in when it is not installed | none |
| `CURL_CA_BUNDLE` | curlike's CA bundle, as in curl | the OS trust store |

The proxy, its credential, its kind and `NO_PROXY` are read by syshttp under
the same prefix.

## Gotchas

- An unsupported flag is exit 2 (`curl: (2) Unsupported options: …`). It is
  never silently ignored, so call the real curl for it.
- `pycurl` never runs the real curl, even when one is installed: a launcher
  makes that choice.
- curlike reads no `.curlrc`, shows no progress meter, and keeps no
  connection alive between redirects.
