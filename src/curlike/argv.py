"""Reading argv the way curl reads it, without parsing it: what the
passthrough and the URL hooks need to know before any path is chosen."""
import argparse

from .options import build_parser
from .request import default_scheme

_STEERING = {
    'proxy': ('-x', '--proxy', '--socks4', '--socks4a', '--socks5', '--socks5-hostname'),
    'noproxy': ('--noproxy',), 'proxy_user': ('-U', '--proxy-user'),
    'url': ('--url',),
}


def _takes_value():
    """``{option string: takes a value?}`` from the command's own parser."""
    table = {}
    for action in build_parser()._actions:
        for opt in action.option_strings:
            table[opt] = action.nargs != 0 and not isinstance(
                action, (argparse._StoreTrueAction, argparse._StoreFalseAction, argparse._CountAction))
    return table


def attach_values(argv):
    """``argv`` with every option value that starts with ``-`` attached to
    its option (``--opt=VALUE``, ``-oVALUE``): curl takes the next argument as
    the value whatever it looks like (``-z -DATE``, ``-d -1``, ``-H -x``),
    argparse refuses one that looks like a flag."""
    takes = _takes_value()
    out, args, i = [], list(argv), 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == '--':
            out.extend(args[i - 1:])
            break
        nxt = args[i] if i < len(args) else None
        dashed = nxt is not None and nxt.startswith('-') and nxt != '-'
        if arg.startswith('--'):
            if '=' not in arg and takes.get(arg) and dashed:
                out.append('%s=%s' % (arg, nxt))
                i += 1
            else:
                out.append(arg)
        elif arg.startswith('-') and len(arg) > 1:
            # A short cluster (-sz) ends at its first value-taking option;
            # only a bare one at the end takes the next argument.
            ends_bare = False
            for j in range(1, len(arg)):
                if takes.get('-' + arg[j]):
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
    walked the way curl reads it, using the shim's own parser only as the
    table of which options take a value: combined short flags (``-sx URL``,
    ``-Uu:p``) and option VALUES that merely look like flags (``-d
    '--proxy=x'``, ``-H --noproxy``) are handled; an unknown ``--opt`` is
    assumed to take no value. (argparse itself refuses a value that starts
    with ``-``, so it cannot be the parser here.)"""
    takes_value, wanted = {}, {}
    for action in build_parser()._actions:
        for opt in action.option_strings:
            takes_value[opt] = action.nargs != 0 and not isinstance(
                action, (argparse._StoreTrueAction, argparse._StoreFalseAction, argparse._CountAction))
            for key, names in _STEERING.items():
                if opt in names:
                    wanted[opt] = key
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
            if not has_eq and takes_value.get(name):
                value = args[i] if i < len(args) else ''
                i += 1
            if name in wanted:
                seen[wanted[name]] = value if takes_value.get(name) else True
        elif arg.startswith('-') and len(arg) > 1:
            j = 1
            while j < len(arg):
                short = '-' + arg[j]
                j += 1
                if takes_value.get(short):
                    value = arg[j:]
                    if not value:
                        value = args[i] if i < len(args) else ''
                        i += 1
                    if short in wanted:
                        seen[wanted[short]] = value
                    break
                if short in wanted:
                    seen[wanted[short]] = True
        else:
            positionals.append(arg)
    return seen, positionals


def caller_steering(argv):
    """``(proxy, noproxy, proxy_user)`` as the caller wrote them, or ``None`` each."""
    seen, _positionals = walk_argv(argv)
    return seen['proxy'], seen['noproxy'], seen['proxy_user']


def requested_url(argv):
    """The URL the caller asked for (``--url`` or the first positional, the
    scheme defaulted as curl defaults it, ``http://``), or ``None``. Never
    the proxy's."""
    seen, positionals = walk_argv(argv)
    url = seen['url'] if isinstance(seen['url'], str) and seen['url'] else (positionals[0] if positionals else None)
    return default_scheme(url) if url else None
