"""What the TLS options trust: a ``--crlfile`` supplies revocation lists and
no trust anchors, and the contexts curlike builds do not apply the strict
X.509 checks Python 3.13 added (a leaf with no Authority Key Identifier)."""

import pathlib
import ssl
import subprocess

import pytest

from test_curl_options import _Echo, _openssl, _serve, pki  # noqa: F401  (fixture reused)
from test_curl_parity import _revocation_and_pins
from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)


def _tls_server(certfile, keyfile):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certfile), str(keyfile))
    httpd = _serve(_Echo, context)
    return httpd, "https://127.0.0.1:%d/x" % httpd.server_address[1]


@pytest.fixture()
def crls(pki, tmp_path):
    return _revocation_and_pins(pki, tmp_path)


def test_a_certificate_in_a_crl_file_is_not_trusted(pki, crls, tmp_path, monkeypatch, capsysbinary):
    httpd, url = _tls_server(pki / "server.pem", pki / "server.key")
    try:
        mixed = tmp_path / "mixed.pem"
        mixed.write_bytes((pki / "ca.pem").read_bytes() + pathlib.Path(crls["crl_clean"]).read_bytes())
        rc, _ = _fallback(monkeypatch, capsysbinary, ["-s", "--crlfile", str(mixed), url])
        assert rc == 60, "the CA inside the CRL file must not make its servers trusted"
        rc, _ = _fallback(
            monkeypatch,
            capsysbinary,
            ["-s", "--cacert", str(pki / "ca.pem"), "--crlfile", crls["crl_clean"], url],
        )
        assert rc == 0, "a real CRL beside a CA given with --cacert verifies"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_a_crl_file_with_no_crl_is_82(pki, tmp_path, monkeypatch, capsysbinary):
    httpd, url = _tls_server(pki / "server.pem", pki / "server.key")
    try:
        rc, out = _fallback(
            monkeypatch, capsysbinary, ["-sS", "--cacert", str(pki / "ca.pem"), "--crlfile", str(pki / "ca.pem"), url]
        )
        assert rc == 82 and b"(82)" in out.err
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_a_leaf_without_an_authority_key_identifier_verifies(pki, tmp_path, monkeypatch, capsysbinary):
    openssl = _openssl()
    (tmp_path / "leaf.ext").write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
        encoding="ascii",
    )

    def run(*argv):
        subprocess.run([openssl, *argv], cwd=str(tmp_path), check=True, capture_output=True)

    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=127.0.0.1")
    run(
        "x509",
        "-req",
        "-in",
        "leaf.csr",
        "-CA",
        str(pki / "ca.pem"),
        "-CAkey",
        str(pki / "ca.key"),
        "-set_serial",
        "9",
        "-out",
        "leaf.pem",
        "-days",
        "30",
        "-extfile",
        "leaf.ext",
    )
    httpd, url = _tls_server(tmp_path / "leaf.pem", tmp_path / "leaf.key")
    try:
        rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "--cacert", str(pki / "ca.pem"), url])
        assert rc == 0, out.err
    finally:
        httpd.shutdown()
        httpd.server_close()
