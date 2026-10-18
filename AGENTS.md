# curlike — contributor orientation

| Shipped header | Covers |
| --- | --- |
| [`src/curlike/AGENTS.md`](src/curlike/AGENTS.md) | the command, its entry points, settings and curl-compatibility contract |

## Layout

- `src/curlike/shim.py` — the drop-in curl: hook wrapper, real curl with the
  proxy added, else the fallback. `__main__.py` runs it.
- `src/curlike/__init__.py` — the fallback's `main` / `run_fallback`. The
  options are duho mixin groups, one module per group (`request`, `body`,
  `output`, `writeout`, `tls`, `connection`, `cookies`), composed in
  `options.CurlCmd`. `transfer` runs the request; `compat` holds every answer
  that differs between curl versions; `unsupported` declares the refused flags.
- `tests/` — pytest. `test_curl_parity.py` runs the fallback and the real curl
  on the same command against raw-socket servers, and is skipped without a
  real curl. `test_proxy_auth.py` and `test_jars_proxy.py` hold fake proxies
  and gateways that other modules import.

## Environment

Python 3.9 or later; venvs under `.pyvenv/<version>-<os>-<arch>/`
(`dotagents pyvenv`). httplib, duho and netimps come from sibling checkouts
until they are on PyPI at the versions declared:

```bash
.pyvenv/<tag>/Scripts/python -m pip install -e ../httplib -e ../duho -e ../netimps -e ".[dev]"
```

## Checks

```bash
.pyvenv/<tag>/Scripts/python -m pytest -q        # about 5 minutes; warnings are errors but ResourceWarning
.pyvenv/<tag>/Scripts/python -m black --check src tests
```

## Conventions

- Every write to stdout goes through `output.Stdout`, which buffers 4096
  bytes the way the C library under curl does. That buffering decides which
  of curl's exit-23 messages applies.
- A version-dependent answer goes in `compat`, measured against a real curl
  build, never inferred from curl's source alone.
- Settings are read through `httplib.env.HTTPEnv`, never `os.environ` by name.

## Releasing

See `README.md` → Releasing.
