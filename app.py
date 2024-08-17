from dotenv import load_dotenv
from flask import Flask
from flask_migrate import Migrate
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
db.init_app(app)
migrate = Migrate(app, db)


login_manager.init_app(app)
login_manager.login_view = 'login'
setup_routes(app)
setup_admin(app, db)

# Content Security Policy (CSP) Header
csp = {
    'default-src': [
        '\'self\'',
        'https://code.jquery.com',
        'https://cdn.jsdelivr.net',
        'https://i.pinimg.com',
        'https://oauth.telegram.org',
        'https://oauth.vk.com'
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
