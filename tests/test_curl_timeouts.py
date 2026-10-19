"""curl's time limits: no limit unless one is asked for, --connect-timeout
bounds the connect only, -m bounds the whole transfer (redirect hops and a
trickling body included)."""

import socket
import threading
import time

import pytest

from test_proxy_auth import _clean_env, _fallback  # noqa: F401  (autouse fixture reused)


def _serve(handler):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)

    def loop():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return

            def run(conn=conn):
                try:
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        piece = conn.recv(65536)
                        if not piece:
                            return
                        buf += piece
                    handler(conn, buf)
                except OSError:
                    pass
                finally:
                    conn.close()

            threading.Thread(target=run, daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return listener, "http://127.0.0.1:%d" % listener.getsockname()[1]


@pytest.fixture()
def serve():
    listeners = []

    def start(handler):
        listener, url = _serve(handler)
        listeners.append(listener)
        return url

    yield start
    for listener in listeners:
        listener.close()


def _late(delay):
    def handler(conn, head):
        time.sleep(delay)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

    return handler


def _trickle(conn, head):
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
    for _ in range(100):
        conn.sendall(b"x")
        time.sleep(0.4)


def test_no_flag_is_no_time_limit(serve, monkeypatch, capsysbinary):
    url = serve(_late(1.5))
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", url])
    assert rc == 0 and out.out == b"ok"


def test_connect_timeout_does_not_cut_off_a_slow_reply(serve, monkeypatch, capsysbinary):
    url = serve(_late(1.5))
    rc, out = _fallback(monkeypatch, capsysbinary, ["-s", "--connect-timeout", "0.5", url])
    assert rc == 0 and out.out == b"ok"


def test_max_time_ends_a_trickling_body_at_the_deadline(serve, monkeypatch, capsysbinary):
    url = serve(_trickle)
    start = time.monotonic()
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "-m", "1.5", url])
    took = time.monotonic() - start
    assert rc == 28 and b"(28) Operation timed out" in out.err
    assert 1.2 < took < 3.0, took


def test_max_time_bounds_the_hops_of_a_redirect_chain(serve, monkeypatch, capsysbinary):
    def hop(conn, head):
        time.sleep(0.7)
        conn.sendall(b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

    url = serve(hop)
    start = time.monotonic()
    rc, out = _fallback(monkeypatch, capsysbinary, ["-sS", "-L", "-m", "2", url])
    assert rc == 28 and time.monotonic() - start < 4
