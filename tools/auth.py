from flask import current_app
from flask import session
from flask_login import LoginManager, login_user, logout_user
from werkzeug.security import check_password_hash

from database.models import User
from database.models import db

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


def authenticate_vk_user(vk_id, user_name, first_name, last_name, email):
    user = User.query.filter_by(vk_id=vk_id).first()

    if not user:
        current_app.logger.debug(f"Creating a new VK user with ID: {vk_id}")
        user = User(username=user_name, vk_id=vk_id, first_name=first_name, last_name=last_name, email=email, provider='vk')
        db.session.add(user)

        try:
            current_app.logger.debug(f"Attempting to commit new VK user to the database")
            db.session.commit()  # Фиксируем транзакцию
            current_app.logger.debug(f"New VK user created and committed to the database with ID: {user.id}")
        except Exception as e:
            current_app.logger.error(f"Failed to commit new VK user to the database. Error: {e}")
            db.session.rollback()  # Откатываем транзакцию в случае ошибки
            current_app.logger.debug("Transaction rolled back")
            return False

    session['loggedin'] = True
    session['id'] = user.id
    session['username'] = user.username
    login_user(user)
    current_app.logger.debug(f"User {user.username} authenticated and logged in")
    return True


def logout():
    logout_user()
    session.clear()
