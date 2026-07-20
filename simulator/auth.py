"""
Tenable.io authentication.

Header: `X-ApiKeys: accessKey=<accessKey>; secretKey=<secretKey>`.
The pack constructs it as: `f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}"`.
"""
import re
from functools import wraps

from flask import jsonify, request

from config import Config


_APIKEY_RE = re.compile(
    r'accessKey\s*=\s*(?P<ak>[^;]+)\s*;\s*secretKey\s*=\s*(?P<sk>[^;]+)',
    re.IGNORECASE,
)


def _extract_keys(header_value):
    if not header_value:
        return None, None
    m = _APIKEY_RE.search(header_value)
    if not m:
        return None, None
    return m.group('ak').strip(), m.group('sk').strip()


def require_api_keys(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ak, sk = _extract_keys(request.headers.get('X-ApiKeys'))
        if ak != Config.AUTH_ACCESS_KEY or sk != Config.AUTH_SECRET_KEY:
            return jsonify({
                'statusCode': 401,
                'error': 'Unauthorized',
                'message': 'Invalid or missing X-ApiKeys header',
            }), 401
        return f(*args, **kwargs)
    return decorated
