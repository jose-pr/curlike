# curlike

**A `curl` that works everywhere Python does.** `pycurl` runs the real curl
when there is one, adding the proxy and credential that
[httplib](https://jose-pr.github.io/httplib/) is configured with. Without
one, it serves the request itself, with curl's exit codes and messages.

```bash
pip install curlike
pycurl -s https://example.com/
```

- [Behaviour](behaviour.md): the supported options, exit codes and settings.
- API reference: `curlike.shim` and `curlike`, in the navigation.
- [Changelog](changelog.md).

Source: <https://github.com/jose-pr/curlike>.
