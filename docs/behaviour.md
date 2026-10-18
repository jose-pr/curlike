# Behaviour

`<P>` is syshttp's settings prefix: `SYSHTTP` unless `SYSHTTP_PREFIX` names another.

    pycurl https://example.com
    pycurl -s -o out.json -H 'Accept: application/json' https://api.example.com/x
    pycurl -X POST -d '{"k":1}' -H 'Content-Type: application/json' https://h/api

- **It uses the configured proxy either way.** Real curl reads only the global
  `http_proxy` vars, never `<P>_PROXY`, so when `<P>_PROXY` is set and you
  did not name a proxy (`-x`) or a bypass list (`--noproxy`), the shim prepends
  `--proxy` plus `--proxy-header 'Proxy-Authorization: …'` (or `--proxy-user`
  for URL userinfo). Your own `-U user:pass` keeps the configured proxy and replaces
  its credential. A **`prefix` gateway is served by the fallback**, not real
  curl: curl cannot express `<proxy><endpoint><url>` per hop (multi-URL, `-L`,
  config files), so the shim speaks the gateway itself and flags it lacks fail
  loud. The fallback resolves the proxy exactly like `syshttp` (`<P>_PROXY`,
  then the global vars; credential and type as below), re-decides **every
  redirect hop** (proxied again, or direct without the credential for a
  `NO_PROXY` host) and honours `NO_PROXY`. `-x` names a proxy of your own
  (always `connect`, never given the configured proxy's credential); `--noproxy`
  (`*` or a host list) replaces `NO_PROXY`, as in curl. A malformed
  `<P>_PROXY`/`<P>_PROXY_TYPE` never blocks real curl (one warning, argv
  as typed); the fallback, which would have to use it, exits 2.
- **`-q` / `--disable`** must be curl's FIRST argument to skip `.curlrc`, so
  the shim keeps a leading one first when it adds the proxy options.
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
  - **`-L` follows as curl does**: credentials (`Authorization` from `-u`,
    `--oauth2-bearer` or `-H`; `Cookie` from `-H` or a `-b` string) go to the
    next hop only while scheme, host and port stay the same, unless
    `--location-trusted`; a `-b` file's cookies are re-chosen per hop; 301/302
    turn a POST into a GET (`--post301`/`--post302` keep it), 303 anything but
    HEAD, 307/308 keep method and body, and `-X` stays forced.
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
    `--ciphers` list. A proxy refusing the https CONNECT is 56, or 7 from curl
    8.20 on (`<P>_CURL_COMPAT`; 22 under `-f`), dropping it 56. The reply: 52
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
    for. `size_delivered` is curl 8.20's: answering as an older curl
    (`<P>_CURL_COMPAT`), it warns and writes nothing, as that curl does. In
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
    transfer's. Older curls differ (`<P>_CURL_COMPAT`): before 8.17 a line
    without a code is not printed under `-s` even with `-S`, and before 8.9
    the wording itself is older (Ubuntu 24.04's 8.5 was measured).
- **Unsupported flags fail loud** (`curl: (2) Unsupported options: --http2`, exit
  2) rather than silently do the wrong thing — that guard is deliberate. If you
  hit one, call real `curl`.
- **`<P>_CURL_SSL_REVOKE`** — certificate revocation for a real curl on
  Windows' Schannel (Git Bash's curl, `System32\curl.exe`), which checks it and
  fails with exit 60 ("the revocation status is unknown") when a certificate's
  revocation list is missing or unreachable — common behind a TLS-inspecting
  proxy — while OpenSSL curls (Linux, macOS) never check. `best-effort`
  (default) adds `--ssl-revoke-best-effort`: a list that is there is checked, a
  missing one is not a failure. `false` adds `--ssl-no-revoke`, `true` adds
  nothing. Only for a Schannel curl, and never when the command names
  `--ssl-no-revoke` / `--ssl-revoke-best-effort` itself. curl has no such
  option for an `https://` proxy's own
  certificate: through one whose certificate has no revocation list, a
  Schannel curl fails whatever is set (the fallback does not: `<P>_CURL=` cannot
  help, but removing the real curl from PATH, or an OpenSSL curl, does). The fallback checks no revocation (as OpenSSL curl) unless
  `--crlfile`.
- **`<P>_CURL_COMPAT`** — the curl version the fallback answers as where curl
  versions disagree (`8.19`, `8.19.0`), or `auto` (default): the real curl on
  PATH, else the newest measured (8.22). It changes only the answers listed in
  `curlike.compat`, each measured against curl's own builds; an
  unreadable value is exit 2.
- **`<P>_CURL=0`** (or `n`/`no`/`false`/`off`) runs the real curl exactly as
  typed — no configured proxy, no hooks, no fallback; exit 2 if there is none. Unset
  or `1`/`y` is the shim.
- Fallback TLS verifies against the **OS trust store** — `syshttp.tls`, the
  same store the requests session uses — unless `--cacert` / `--capath` or
  `$CURL_CA_BUNDLE` name one, which replaces it as in curl; `-k/--insecure`
  disables verification. `--cert file[:password]` (the file may hold the key),
  `--key`, `--pass` present a client certificate, PEM only.
- `-v` prints the proxy with the password redacted; nothing here logs a credential.
