"""Answering a 401 / 407 challenge, once: Digest (RFC 7616, MD5 and SHA-256)
and, under ``--anyauth``, Basic. One implementation serves a server
(``--digest``, ``--anyauth``), a plain proxy and a proxy's CONNECT
(``--proxy-digest``, ``--proxy-anyauth``). A credential the other side
rejects is not sent again: the 401 / 407 is the response, as in curl."""

import base64
import hashlib
import os
import urllib.request


def _quoted(value):
    """``value`` as the inside of a quoted string (RFC 7230 section 3.2.6)."""
    return value.replace('\\', '\\\\').replace('"', '\\"')


def _digest_function(algorithm):
    """The hash for a Digest ``algorithm`` (``-sess`` aside), or ``None``."""
    name = {'MD5': 'md5', 'SHA-256': 'sha256', 'SHA-512-256': 'sha512_256'}.get(algorithm.replace('-SESS', ''))
    if name is None:
        return None
    try:
        hashlib.new(name)
    except ValueError:
        return None  # the build has no such hash
    return lambda text: hashlib.new(name, text.encode('utf-8')).hexdigest()


def digest_authorization(challenge, user, password, method, uri):
    """RFC 7616 Digest (``qop=auth`` when offered) for one challenge, or
    ``None`` when its algorithm is not one this build has."""
    fields = urllib.request.parse_keqv_list(urllib.request.parse_http_list(challenge.split(None, 1)[1]))
    algorithm = (fields.get('algorithm') or 'MD5').upper()
    h = _digest_function(algorithm)
    if h is None:
        return None
    realm, nonce = fields.get('realm', ''), fields.get('nonce', '')
    ha1 = h('%s:%s:%s' % (user, realm, password))
    cnonce = os.urandom(8).hex()
    if algorithm.endswith('-SESS'):
        ha1 = h('%s:%s:%s' % (ha1, nonce, cnonce))
    ha2 = h('%s:%s' % (method, uri))
    qops = [q.strip() for q in fields.get('qop', '').split(',') if q.strip()]
    parts = [
        'username="%s"' % _quoted(user),
        'realm="%s"' % _quoted(realm),
        'nonce="%s"' % _quoted(nonce),
        'uri="%s"' % _quoted(uri),
    ]
    if 'auth' in qops:
        response = h('%s:%s:00000001:%s:auth:%s' % (ha1, nonce, cnonce, ha2))
        parts += ['cnonce="%s"' % cnonce, 'nc=00000001', 'qop=auth']
    else:
        response = h('%s:%s:%s' % (ha1, nonce, ha2))
    parts.append('response="%s"' % response)
    if fields.get('opaque'):
        parts.append('opaque="%s"' % _quoted(fields['opaque']))
    if fields.get('algorithm'):
        parts.append('algorithm=%s' % fields['algorithm'])
    return 'Digest ' + ', '.join(parts)


class ChallengeAuth(object):
    """Credentials that answer a challenge with Digest or, for ``anyauth``,
    Basic when that is all it offers. Nothing is sent up front."""

    def __init__(self, user, password, anyauth=False):
        self.user, self.password, self.anyauth = user, password, anyauth

    def answer(self, challenges, method, uri):
        """The ``Authorization`` / ``Proxy-Authorization`` value for
        ``challenges`` (the 401's / 407's ``WWW-Authenticate`` /
        ``Proxy-Authenticate`` values), or ``None`` when none is one this can
        answer."""
        for challenge in challenges:
            if challenge.strip().lower().startswith('digest'):
                answer = digest_authorization(challenge, self.user, self.password, method, uri)
                if answer is not None:
                    return answer
        if self.anyauth and any(c.strip().lower().startswith('basic') for c in challenges):
            token = base64.b64encode(('%s:%s' % (self.user, self.password)).encode('utf-8')).decode('ascii')
            return 'Basic ' + token
        return None


class ChallengeHandler(urllib.request.BaseHandler):
    """Answers a 401 (``proxy=False``) or a 407 (``proxy=True``) once with
    ``auth``. A request that already carries the credential, or a challenge
    nothing here can answer, leaves the response as it is. ``allowed(req)``
    says whether the credential may be sent with ``req`` at all."""

    def __init__(self, auth, proxy=False, allowed=None):
        self.auth = auth
        self.proxy = proxy
        self.allowed = allowed
        self.status = 407 if proxy else 401
        self.challenge_header = 'Proxy-Authenticate' if proxy else 'WWW-Authenticate'
        self.answer_header = 'Proxy-Authorization' if proxy else 'Authorization'

    def _answer(self, req, fp, code, headers):
        if code != self.status or req.has_header(self.answer_header.capitalize()):  # urllib's key form
            return None
        challenges = headers.get_all(self.challenge_header) or []
        if not challenges or (self.allowed is not None and not self.allowed(req)):
            return None
        value = self.auth.answer(challenges, req.get_method(), req.selector)
        if value is None:
            return None
        fp.close()
        req.add_unredirected_header(self.answer_header, value)
        return self.parent.open(req, timeout=req.timeout)

    def http_error_401(self, req, fp, code, msg, headers):
        return self._answer(req, fp, code, headers)

    http_error_407 = http_error_401
