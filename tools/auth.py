from flask import session
from flask_login import LoginManager, login_user, logout_user
from werkzeug.security import check_password_hash

from database.models import User

login_manager = LoginManager()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def authenticate_user(username, password):
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        session['loggedin'] = True
        session['id'] = user.id
        session['username'] = user.username
        login_user(user)
        return True
    return False


def logout():
    logout_user()
