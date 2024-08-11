from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_admin import Admin
from flask_talisman import Talisman
from database.models import db
from core.admin import setup_admin
from core.routes import setup_routes
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
from tools.config import Config
import os

load_dotenv()

app = Flask(__name__)
talisman = Talisman(app)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)

admin = Admin(app, name='Admin Panel', template_mode='bootstrap4')
setup_admin(admin, db)
setup_routes(app)

# Content Security Policy (CSP) Header
csp = {
    'default-src': [
        '\'self\'',
        'https://code.jquery.com',
        'https://cdn.jsdelivr.net'
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
