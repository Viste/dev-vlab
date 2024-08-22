import base64
import hashlib
import os
from functools import wraps

import jwt
from flask import request, jsonify

from tools.config import Config


def generate_jwt():
    payload = {
        "iss": "telegram_bot"
    }
    token = jwt.encode(payload, Config.TELEGRAM_BOT_SECRET, algorithm="HS256")
    return token


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split()[1]

        if not token:
            return jsonify({"message": "Token is missing!"}), 403

        try:
            jwt.decode(token, Config.TELEGRAM_BOT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token!"}), 403

        return f(*args, **kwargs)
    return decorated


def generate_code_verifier():
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('utf-8')


def generate_code_challenge(code_verifier):
    digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('utf-8')


code_verifier = generate_code_verifier()
code_challenge = generate_code_challenge(code_verifier)
