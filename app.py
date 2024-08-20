import logging

from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import Flask
from flask_migrate import Migrate
from flask_session import Session
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix

from core.admin import setup_admin
from core.routes import setup_routes
from database.models import db
from tools.auth import login_manager
from tools.config import Config

load_dotenv()

app = Flask(__name__)
talisman = Talisman(app)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)
app.config.from_object(Config)

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('sqlalchemy.engine').setLevel(logging.DEBUG)
logging.getLogger('sqlalchemy.pool').setLevel(logging.DEBUG)
logging.getLogger('sqlalchemy.dialects').setLevel(logging.DEBUG)

db.init_app(app)
Session(app)
migrate = Migrate(app, db)


login_manager.init_app(app)
login_manager.login_view = 'login'
oauth = OAuth()
setup_routes(app, oauth)
setup_admin(app, db)

# Content Security Policy (CSP) Header
csp = {
    'default-src': [
        '\'self\'',
        'https://code.jquery.com',
        'https://cdn.jsdelivr.net',
        'https://fonts.googleapis.com',
        'https://cdnjs.cloudflare.com',
        'https://i.pinimg.com',
        'https://oauth.telegram.org',
        'https://oauth.vk.com',
        'https://cdn4.cdn-telegram.org',
        'https://id.vk.com',
        'https://encrypted-tbn0.gstatic.com'
    ]
}
# HTTP Strict Transport Security (HSTS) Header
hsts = {
    'max-age': 31536000,
    'includeSubDomains': True
}
# Enforce HTTPS and other headers
talisman.force_https = True
talisman.force_file_save = True
talisman.x_xss_protection = True
talisman.session_cookie_secure = True
talisman.session_cookie_samesite = 'Lax'
talisman.frame_options_allow_from = 'https://www.google.com'

# Add the headers to Talisman
talisman.content_security_policy = csp
talisman.strict_transport_security = hsts

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True, use_reloader=False)
