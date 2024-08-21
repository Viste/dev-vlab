from flask import current_app
from flask import session
from flask_login import LoginManager, login_user, logout_user
from telethon.sync import TelegramClient
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


def authenticate_telegram_user(phone_number, api_id, api_hash):
    client = TelegramClient('session_name', api_id, api_hash)

    try:
        client.connect()
        if not client.is_user_authorized():
            client.send_code_request(phone_number)
            code = input('Enter the code you received: ')
            client.sign_in(phone_number, code)

        user_info = client.get_me()
        user = User.query.filter_by(telegram_id=user_info.id).first()

        if not user:
            # Если у пользователя нет username, создаем его на основе других данных
            username = user_info.username if user_info.username else f"telegram_{user_info.id}"
            user = User(
                username=username,
                telegram_id=user_info.id,
                first_name=user_info.first_name,
                last_name=user_info.last_name,
            )
            db.session.add(user)
            db.session.commit()

        session['loggedin'] = True
        session['id'] = user.id
        session['username'] = user.username
        login_user(user)

        client.disconnect()
        return True

    except Exception as e:
        current_app.logger.error(f"Failed to authenticate via Telegram. Error: {e}")
        return False


def logout():
    logout_user()
    session.clear()
