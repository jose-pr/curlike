"""Reading argv the way curl reads it, without parsing it: what the
passthrough and the URL hooks need to know before any path is chosen."""

_TABLE = '''
    -A -C -D -E -F -H -K -P -Q -T -U -X -Y -b -c -d -e -h -m -o -r -t -u -w -x -y -z --abstract-unix-socket
    --alt-svc --aws-sigv4 --cacert --capath --cert --cert-type --ciphers --config --connect-timeout --connect-to
    --continue-at --cookie --cookie-jar --create-file-mode --crlfile --curves --data --data-ascii --data-binary
    --data-raw --data-urlencode --delegation --dns-interface --dns-ipv4-addr --dns-ipv6-addr --dns-servers
    --doh-url --dump-header --ech --egd-file --engine --etag-compare --etag-save --expect100-timeout --form
    --form-string --ftp-account --ftp-alternative-to-user --ftp-method --ftp-port --ftp-ssl-ccc-mode
    --happy-eyeballs-timeout-ms --haproxy-clientip --header --help --hostpubmd5 --hostpubsha256 --hsts
    --httpsig-algo --httpsig-headers --httpsig-key --httpsig-keyid --interface --ip-tos --ipfs-gateway --json
    --keepalive-cnt --keepalive-time --key --key-type --knownhosts --krb --krb4 --libcurl --limit-rate
    --local-port --login-options --mail-auth --mail-from --mail-rcpt --max-filesize --max-redirs --max-time
    --netrc-file --noproxy --oauth2-bearer --output --output-dir --parallel-max --parallel-max-host --pass
    --pinnedpubkey --preproxy --proto --proto-default --proto-redir --proxy --proxy-cacert --proxy-capath
    --proxy-cert --proxy-cert-type --proxy-ciphers --proxy-crlfile --proxy-header --proxy-key --proxy-key-type
    --proxy-pass --proxy-pinnedpubkey --proxy-service-name --proxy-tls13-ciphers --proxy-tlsauthtype
    --proxy-tlspassword --proxy-tlsuser --proxy-user --proxy1.0 --pubkey --quote --random-file --range --rate
    --referer --request --request-target --resolve --retry --retry-delay --retry-max-time --sasl-authzid
    --service-name --sigalgs --socks4 --socks4a --socks5 --socks5-gssapi-service --socks5-hostname --speed-limit
    --speed-time --ssl-sessions --stderr --telnet-option --tftp-blksize --time-cond --tls-max --tls13-ciphers
    --tlsauthtype --tlspassword --tlsuser --trace --trace-ascii --trace-config --unix-socket --upload-file
    --upload-flags --url --url-query --user --user-agent --variable --vlan-priority --write-out
'''

#: The options of curl 8.23 that take an argument, short and long, from the
#: option table its ``--help all`` is made from (``--krb4`` is deprecated and
#: not listed there, but curl still reads its argument). Every other option, a
#: ``--no-NAME`` and an unknown one stand alone.
VALUE_OPTIONS = frozenset(_TABLE.split())

# Each key is one thing ``walk_argv`` reports: the options that set it, last one wins.
_STEERING = {
    'proxy': ('-x', '--proxy', '--proxy1.0', '--preproxy', '--socks4', '--socks4a', '--socks5', '--socks5-hostname'),
    'config': ('-K', '--config'),
    'noproxy': ('--noproxy',),
    'proxy_user': ('-U', '--proxy-user'),
    'url': ('--url',),
}
_WANTED = {option: key for key, options in _STEERING.items() for option in options}


def _name(option):
    """``--expand-NAME`` (``--NAME`` with variables expanded) as ``--NAME``."""
    return '--' + option[len('--expand-') :] if option.startswith('--expand-') else option


def _takes_value(option):
    """Whether ``option`` (``--name`` or ``-x``) takes an argument in curl, or
    is ``--timeout``, which only this command has."""
    option = _name(option)
    return option in VALUE_OPTIONS or option == '--timeout'


def _argparse_takes_value(option):
    """:func:`_takes_value` for argparse: its ``-h`` / ``--help`` takes no
    argument, where curl's takes a category."""
    return option not in ('-h', '--help') and _takes_value(option)


def attach_values(argv):
    """``argv`` with every option value that starts with ``-`` attached to
    its option (``--opt=VALUE``, ``-oVALUE``): curl takes the next argument as
    the value whatever it looks like (``-z -DATE``, ``-d -1``, ``-H -x``),
    argparse refuses one that looks like a flag."""
    out, args, i = [], list(argv), 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == '--':
            out.extend(args[i - 1 :])
            break
        nxt = args[i] if i < len(args) else None
        dashed = nxt is not None and nxt.startswith('-') and nxt != '-'
        if arg.startswith('--'):
            if '=' not in arg and _argparse_takes_value(arg) and dashed:
                out.append('%s=%s' % (arg, nxt))
                i += 1
            else:
                out.append(arg)
        elif arg.startswith('-') and len(arg) > 1:
            # A short cluster (-sz) ends at its first value-taking option;
            # only a bare one at the end takes the next argument.
            ends_bare = False
            for j in range(1, len(arg)):
                if _argparse_takes_value('-' + arg[j]):
                    ends_bare = j == len(arg) - 1
                    break
            if ends_bare and dashed:
                out.append(arg + nxt)
                i += 1
            else:
                out.append(arg)
        else:
            out.append(arg)
    return out


def walk_argv(argv):
    """``(seen, positionals)``: the ``_STEERING`` options as the caller wrote
    them (``None`` each when absent) and the positional arguments. argv is
    walked the way curl reads it, with :data:`VALUE_OPTIONS` as the table of
    which options take a value: combined short flags (``-sx URL``,
    ``-Uu:p``) and option VALUES that merely look like flags (``-d
    '--proxy=x'``, ``-H --noproxy``) are handled; an unknown ``--opt`` is
    assumed to take no value."""
    seen = {key: None for key in _STEERING}
    positionals = []
    args = list(argv)
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == '--':
            positionals.extend(args[i:])
            break
        if arg.startswith('--'):
            name, has_eq, value = arg.partition('=')
            if not has_eq and _takes_value(name):
                value = args[i] if i < len(args) else ''
                i += 1
            if _name(name) in _WANTED:
                seen[_WANTED[_name(name)]] = value if _takes_value(name) else True
        elif arg.startswith('-') and len(arg) > 1:
            j = 1
            while j < len(arg):
                short = '-' + arg[j]
                j += 1
                if _takes_value(short):
                    value = arg[j:]
                    if not value:
                        value = args[i] if i < len(args) else ''
                        i += 1
                    if short in _WANTED:
                        seen[_WANTED[short]] = value
                    break
                if short in _WANTED:
                    seen[_WANTED[short]] = True
        else:
            positionals.append(arg)
    return seen, positionals


def caller_steering(argv):
    """``(proxy, noproxy, proxy_user)`` as the caller wrote them, or ``None``
    each. ``proxy`` is the value of the last of ``-x``, ``--proxy``,
    ``--proxy1.0``, ``--preproxy`` and ``--socks*``; failing that, of the last
    ``-K`` / ``--config``: a config file may name a proxy and is not read
    here, so its name stands for one."""
    seen, _positionals = walk_argv(argv)
    proxy = seen['proxy']
    if not proxy and seen['config']:
        proxy = seen['config']
    return proxy, seen['noproxy'], seen['proxy_user']


def requested_url(argv):
    """The URL the caller asked for (``--url`` or the first positional, the
    scheme defaulted as curl defaults it, ``http://``), or ``None``. Never
    an option's value, nor the proxy's."""
    from .request import default_scheme

    seen, positionals = walk_argv(argv)
    url = seen['url'] if isinstance(seen['url'], str) and seen['url'] else (positionals[0] if positionals else None)
    return default_scheme(url) if url else None
