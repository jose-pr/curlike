# curlike

**A `curl` that works everywhere Python does.** `pycurl` is a
curl-compatible command in pure Python, with curl's exit codes and messages,
routed by [syshttp](https://jose-pr.github.io/syshttp/). It never runs the
real curl.

```bash
pip install curlike
pycurl -s https://example.com/
```

- [Behaviour](behaviour.md): the supported options, exit codes and settings.
- API reference: `curlike`, in the navigation.
- [Changelog](changelog.md).

Source: <https://github.com/jose-pr/curlike>.
