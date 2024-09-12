import base64
import hashlib
import os
import secrets
from functools import wraps

import jwt
import markdown
from PIL import Image
from flask import request, jsonify, current_app

from tools.config import Config


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(current_app.root_path, 'static/profile_pics', picture_fn)

    # Изменение размера изображения
    output_size = (125, 125)
    img = Image.open(form_picture)
    img.thumbnail(output_size)
    img.save(picture_path)

    return picture_fn


def markdown_format(text):
    return markdown.markdown(text, extensions=['extra', 'smarty'])


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
