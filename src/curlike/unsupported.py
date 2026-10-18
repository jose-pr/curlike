"""Flags curl has and the fallback does not honour. Each is declared -- hidden
from ``--help`` -- so it parses, then refused out loud (``NotImplementedError``,
exit 2): the fallback must never silently do the wrong thing for a flag it
does not actually honour. With a real curl on PATH none of this applies --
real curl runs the command."""

import argparse
from typing import List, Optional

from ._duho import Meta, Arg, duho
from .args import Group

_HIDDEN = Meta(help=argparse.SUPPRESS)

#: The fields below; a set one is refused.
UNSUPPORTED_ARGS = [
    'append',
    'cert_status',
    'config',
    'crlf',
    'delegation',
    'disable_eprt',
    'disable_epsv',
    'engine',
    'ftp_account',
    'ftp_alternative_to_user',
    'ftp_create_dirs',
    'ftp_method',
    'ftp_pasv',
    'ftp_skip_pasv_ip',
    'ftp_ssl_ccc_mode',
    'ftp_ssl_ccc',
    'ftp_ssl_control',
    'haproxy_protocol',
    'hostpubmd5',
    'http2_prior_knowledge',
    'http2',
    'http3',
    'ip_resolve',
    'krb',
    'libcurl',
    'list_only',
    'login_options',
    'mail_auth',
    'mail_from',
    'mail_rcpt_allowfails',
    'mail_rcpt',
    'metalink',
    'negotiate',
    'next',
    'no_progress_bar',
    'ntlm_wb',
    'ntlm',
    'parallel_immediate',
    'parallel_max',
    'parallel',
    'proxy_negotiate',
    'proxy_ntlm',
    'proxy_service_name',
    'proxy_ssl_allow_beast',
    'proxy_ssl_auto_client_cert',
    'proxy_tls13_ciphers',
    'proxy_tlsauthtype',
    'proxy_tlspassword',
    'proxy_tlsuser',
    'pubkey',
    'quote',
    'raw',
    'sasl_authzid',
    'sasl_ir',
    'service_name',
    'socks5_gssapi_nec',
    'socks5_gssapi_service',
    'socks5_gssapi',
    'ssl_allow_beast',
    'ssl_auto_client_cert',
    'ssl_reqd',
    'ssl',
    'sslv2',
    'sslv3',
    'telnet_option',
    'tftp_blksize',
    'tftp_no_options',
    'tls13_ciphers',
    'tlsauthtype',
    'tlspassword',
    'tlsuser',
    'tr_encoding',
    'trace_ascii',
    'trace_time',
    'trace',
    'use_ascii',
    'variable',
    'vsock',
    'xattr',
]


class UnsupportedArgs(Group):
    """Recognised-but-unsupported flags, refused by ``_check``."""

    append: Arg[bool, _HIDDEN] = False
    (
        '-a',
        '--append',
    )

    cert_status: Arg[bool, _HIDDEN] = False
    ('--cert-status',)

    config: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='CONFIG')] = None
    (
        '-K',
        '--config',
    )

    crlf: Arg[bool, _HIDDEN] = False
    ('--crlf',)

    delegation: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='LEVEL')] = None
    ('--delegation',)

    disable_eprt: Arg[bool, _HIDDEN] = False
    ('--disable-eprt',)

    disable_epsv: Arg[bool, _HIDDEN] = False
    ('--disable-epsv',)

    engine: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='ENGINE')] = None
    ('--engine',)

    ftp_account: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='DATA')] = None
    ('--ftp-account',)

    ftp_alternative_to_user: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='COMMAND')] = None
    ('--ftp-alternative-to-user',)

    ftp_create_dirs: Arg[bool, _HIDDEN] = False
    ('--ftp-create-dirs',)

    ftp_method: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='METHOD')] = None
    ('--ftp-method',)

    ftp_pasv: Arg[bool, _HIDDEN] = False
    ('--ftp-pasv',)

    ftp_skip_pasv_ip: Arg[bool, _HIDDEN] = False
    ('--ftp-skip-pasv-ip',)

    ftp_ssl_ccc_mode: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='MODE')] = None
    ('--ftp-ssl-ccc-mode',)

    ftp_ssl_ccc: Arg[bool, _HIDDEN] = False
    ('--ftp-ssl-ccc',)

    ftp_ssl_control: Arg[bool, _HIDDEN] = False
    ('--ftp-ssl-control',)

    haproxy_protocol: Arg[bool, _HIDDEN] = False
    ('--haproxy-protocol',)

    hostpubmd5: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='MD5')] = None
    ('--hostpubmd5',)

    http2_prior_knowledge: Arg[bool, _HIDDEN] = False
    ('--http2-prior-knowledge',)

    http2: Arg[bool, _HIDDEN] = False
    ('--http2',)

    http3: Arg[bool, _HIDDEN] = False
    ('--http3',)

    ip_resolve: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='RESOLVE')] = None
    ('--ip-resolve',)

    krb: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='LEVEL')] = None
    ('--krb',)

    libcurl: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='FILE')] = None
    ('--libcurl',)

    list_only: Arg[bool, _HIDDEN] = False
    (
        '-l',
        '--list-only',
    )

    login_options: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='OPTIONS')] = None
    ('--login-options',)

    mail_auth: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='AUTH')] = None
    ('--mail-auth',)

    mail_from: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='FROM')] = None
    ('--mail-from',)

    mail_rcpt_allowfails: Arg[bool, _HIDDEN] = False
    ('--mail-rcpt-allowfails',)

    mail_rcpt: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='RCPT')] = None
    ('--mail-rcpt',)

    metalink: Arg[bool, _HIDDEN] = False
    ('--metalink',)

    negotiate: Arg[bool, _HIDDEN] = False
    ('--negotiate',)

    next: Arg[bool, _HIDDEN] = False
    (
        '-:',
        '--next',
    )

    no_progress_bar: Arg[bool, _HIDDEN] = False
    ('--no-progress-bar',)

    ntlm_wb: Arg[bool, _HIDDEN] = False
    ('--ntlm-wb',)

    ntlm: Arg[bool, _HIDDEN] = False
    ('--ntlm',)

    parallel_immediate: Arg[bool, _HIDDEN] = False
    ('--parallel-immediate',)

    parallel_max: Arg[Optional[int], _HIDDEN] = None
    ('--parallel-max',)

    parallel: Arg[bool, _HIDDEN] = False
    (
        '-Z',
        '--parallel',
    )

    proxy_negotiate: Arg[bool, _HIDDEN] = False
    ('--proxy-negotiate',)

    proxy_ntlm: Arg[bool, _HIDDEN] = False
    ('--proxy-ntlm',)

    proxy_service_name: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='NAME')] = None
    ('--proxy-service-name',)

    proxy_ssl_allow_beast: Arg[bool, _HIDDEN] = False
    ('--proxy-ssl-allow-beast',)

    proxy_ssl_auto_client_cert: Arg[bool, _HIDDEN] = False
    ('--proxy-ssl-auto-client-cert',)

    proxy_tls13_ciphers: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='CIPHERS')] = None
    ('--proxy-tls13-ciphers',)

    proxy_tlsauthtype: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='TYPE')] = None
    ('--proxy-tlsauthtype',)

    proxy_tlspassword: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='STRING')] = None
    ('--proxy-tlspassword',)

    proxy_tlsuser: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='USER')] = None
    ('--proxy-tlsuser',)

    pubkey: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='KEY')] = None
    ('--pubkey',)

    quote: Arg[Optional[List[str]], _HIDDEN] = None
    ('-Q', '--quote')

    raw: Arg[bool, _HIDDEN] = False
    ('--raw',)

    sasl_authzid: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='IDENTITY')] = None
    ('--sasl-authzid',)

    sasl_ir: Arg[bool, _HIDDEN] = False
    ('--sasl-ir',)

    service_name: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='NAME')] = None
    ('--service-name',)

    socks5_gssapi_nec: Arg[bool, _HIDDEN] = False
    ('--socks5-gssapi-nec',)

    socks5_gssapi_service: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='NAME')] = None
    ('--socks5-gssapi-service',)

    socks5_gssapi: Arg[bool, _HIDDEN] = False
    ('--socks5-gssapi',)

    ssl_allow_beast: Arg[bool, _HIDDEN] = False
    ('--ssl-allow-beast',)

    ssl_auto_client_cert: Arg[bool, _HIDDEN] = False
    ('--ssl-auto-client-cert',)

    ssl_reqd: Arg[bool, _HIDDEN] = False
    ('--ssl-reqd',)

    ssl: Arg[bool, _HIDDEN] = False
    ('--ssl',)

    sslv2: Arg[bool, _HIDDEN] = False
    (
        '-2',
        '--sslv2',
    )

    sslv3: Arg[bool, _HIDDEN] = False
    (
        '-3',
        '--sslv3',
    )

    telnet_option: Arg[Optional[List[str]], _HIDDEN] = None
    (
        '-t',
        '--telnet-option',
    )

    tftp_blksize: Arg[Optional[int], _HIDDEN] = None
    ('--tftp-blksize',)

    tftp_no_options: Arg[bool, _HIDDEN] = False
    ('--tftp-no-options',)

    tls13_ciphers: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='CIPHERS')] = None
    ('--tls13-ciphers',)

    tlsauthtype: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='TYPE')] = None
    ('--tlsauthtype',)

    tlspassword: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='STRING')] = None
    ('--tlspassword',)

    tlsuser: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='USER')] = None
    ('--tlsuser',)

    tr_encoding: Arg[bool, _HIDDEN] = False
    ('--tr-encoding',)

    trace_ascii: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='FILE')] = None
    ('--trace-ascii',)

    trace_time: Arg[bool, _HIDDEN] = False
    ('--trace-time',)

    trace: Arg[Optional[str], Meta(help=argparse.SUPPRESS, metavar='FILE')] = None
    ('--trace',)

    use_ascii: Arg[bool, _HIDDEN] = False
    (
        '-B',
        '--use-ascii',
    )

    variable: Arg[Optional[List[str]], _HIDDEN] = None
    ('--variable',)

    vsock: Arg[bool, _HIDDEN] = False
    ('--vsock',)

    xattr: Arg[bool, _HIDDEN] = False
    ('--xattr',)

    def _check(self):
        # The flag as curl spells it (--http1.0, not a name derived from the field).
        spelled = {a.dest: max(a.option_strings, key=len) for a in duho.parser(type(self))._actions if a.option_strings}
        unsupported = [spelled.get(name, '--' + name) for name in UNSUPPORTED_ARGS if getattr(self, name, None)]
        if unsupported:
            raise NotImplementedError('Unsupported options: %s' % ', '.join(unsupported))
