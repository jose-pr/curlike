"""A fake SOCKS4/4a/5 server for probing and tests: ``mode`` picks how it
answers -- 'ok' (no auth), 'auth' (user agent / s3cret required), 'refuse'
(reply 5 / 91), 'unreachable' (reply 4), 'drop' (close at once). Hosts are
resolved by the server for a name request; ``seen`` records each request's
target as the client sent it."""
import socket
import struct
import threading


def _pipe(a, b):
    def fwd(x, y):
        try:
            while True:
                d = x.recv(65536)
                if not d:
                    break
                y.sendall(d)
        except OSError:
            pass
        finally:
            try:
                y.shutdown(socket.SHUT_WR)
            except OSError:
                pass
    t = threading.Thread(target=fwd, args=(b, a), daemon=True)
    t.start()
    fwd(a, b)
    t.join(5)


def _exact(c, n):
    data = b""
    while len(data) < n:
        d = c.recv(n - len(data))
        if not d:
            raise OSError("closed")
        data += d
    return data


class FakeSocks(object):
    def __init__(self, mode="ok"):
        self.mode = mode
        self.seen = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(20)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        try:
            if self.mode == "drop":
                return
            first = _exact(c, 1)
            if first == b"\x04":
                return self._socks4(c)
            if first == b"\x05":
                return self._socks5(c)
        except OSError:
            pass
        finally:
            c.close()

    def _connect(self, host, port):
        return socket.create_connection((host, port), timeout=5)

    def _socks4(self, c):
        cmd, port = struct.unpack("!BH", _exact(c, 3))
        ip = _exact(c, 4)
        user = b""
        while True:
            ch = _exact(c, 1)
            if ch == b"\x00":
                break
            user += ch
        if ip[:3] == b"\x00\x00\x00" and ip[3] != 0:  # 4a: a name follows
            name = b""
            while True:
                ch = _exact(c, 1)
                if ch == b"\x00":
                    break
                name += ch
            host = name.decode()
            self.seen.append(("4a", host, port))
        else:
            host = socket.inet_ntoa(ip)
            self.seen.append(("4", host, port))
        if self.mode in ("refuse", "unreachable"):
            c.sendall(b"\x00\x5b" + b"\x00" * 6)
            return
        try:
            up = self._connect(host, port)
        except OSError:
            c.sendall(b"\x00\x5b" + b"\x00" * 6)
            return
        c.sendall(b"\x00\x5a" + b"\x00" * 6)
        _pipe(c, up)

    def _socks5(self, c):
        count = _exact(c, 1)[0]
        methods = _exact(c, count)
        if self.mode == "auth":
            if b"\x02" not in methods:
                c.sendall(b"\x05\xff")
                return
            c.sendall(b"\x05\x02")
            _exact(c, 1)
            user = _exact(c, _exact(c, 1)[0])
            password = _exact(c, _exact(c, 1)[0])
            if (user, password) != (b"agent", b"s3cret"):
                c.sendall(b"\x01\x01")
                return
            c.sendall(b"\x01\x00")
        else:
            if b"\x00" not in methods:
                c.sendall(b"\x05\xff")
                return
            c.sendall(b"\x05\x00")
        _ver, cmd, _rsv, atyp = _exact(c, 4)
        if atyp == 1:
            host = socket.inet_ntoa(_exact(c, 4))
            kind = "5-ipv4"
        elif atyp == 3:
            host = _exact(c, _exact(c, 1)[0]).decode()
            kind = "5-name"
        else:
            host = socket.inet_ntop(socket.AF_INET6, _exact(c, 16))
            kind = "5-ipv6"
        port = struct.unpack("!H", _exact(c, 2))[0]
        self.seen.append((kind, host, port))
        if self.mode == "refuse":
            c.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
            return
        if self.mode == "unreachable":
            c.sendall(b"\x05\x04\x00\x01" + b"\x00" * 6)
            return
        try:
            up = self._connect(host, port)
        except OSError:
            c.sendall(b"\x05\x04\x00\x01" + b"\x00" * 6)
            return
        c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 0))
        _pipe(c, up)

    def close(self):
        self.sock.close()
