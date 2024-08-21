import logging

import requests
from flask import render_template, redirect, url_for, request, flash, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from telethon.sync import TelegramClient

from database.models import db, Project, BlogPost, NavigationLink, User, Comment
from tools.auth import authenticate_user, authenticate_vk_user
from tools.config import Config
from tools.utils import generate_code_verifier, generate_code_challenge

logging.basicConfig(level=logging.DEBUG)

logging.getLogger('sqlalchemy.engine').setLevel(logging.DEBUG)
logging.getLogger('sqlalchemy.pool').setLevel(logging.DEBUG)
logging.getLogger('sqlalchemy.dialects').setLevel(logging.DEBUG)


def setup_routes(app, oauth):
    oauth.init_app(app)
    vk = oauth.register(
        name='vk',
        client_id=Config.VK_CLIENT_ID,
        client_secret=Config.VK_CLIENT_SECRET,
        authorize_url='https://id.vk.com/authorize',
        access_token_url='https://id.vk.com/oauth2/auth',
        client_kwargs={
            'scope': 'email',
            'token_endpoint_auth_method': 'client_secret_post',
            'token_placement': 'header',
            'response_type': 'code'
        },
    )

    @app.route('/')
    def index():
        projects = Project.query.all()
        links = NavigationLink.query.all()
        return render_template('index.html', nick="Viste", projects=projects, links=links)

    @app.route('/profile')
    @login_required
    def profile():
        return render_template('auth/profile.html', user=current_user)

    @app.route('/blog')
    def blog():
        posts = BlogPost.query.all()
        return render_template('blog/blog.html', posts=posts)

    @app.route('/blog/<int:post_id>')
    @login_required
    def view_post(post_id):
        post = BlogPost.query.get_or_404(post_id)
        return render_template('blog/view_post.html', post=post)

    @app.route('/add_comment/<int:post_id>', methods=['POST'])
    @login_required
    def add_comment(post_id):
        content = request.form['comment']
        post = BlogPost.query.get_or_404(post_id)
        comment = Comment(content=content, post=post)
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('view_post', post_id=post_id))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            if authenticate_user(username, password):
                next_page = request.args.get('next')
                current_app.logger.debug(f"User {username} authenticated successfully. Redirecting to {next_page or 'index'}.")
                return redirect(next_page) if next_page else redirect(url_for('index'))
            else:
                flash('Login Unsuccessful. Please check username and password', 'danger')
                current_app.logger.debug(f"User {username} failed to authenticate.")

        return render_template('auth/login.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()
            if user:
                flash('Username already exists.', 'danger')
                current_app.logger.debug(f"Registration failed: Username {username} already exists.")
                return redirect(url_for('register'))
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            current_app.logger.debug(f"User {username} registered and logged in successfully.")
            return redirect(url_for('index'))
        return render_template('auth/register.html')

    @app.route('/reset_password', methods=['GET', 'POST'])
    @login_required
    def reset_password():
        if request.method == 'POST':
            username = request.form['username']
            user = User.query.filter_by(username=username).first()
            if not user:
                flash('No account found with that username.', 'danger')
                current_app.logger.debug(f"Password reset failed: No account found for username {username}.")
                return redirect(url_for('reset_password'))
            reset_token = user.get_reset_token()
            current_app.logger.debug(f"Password reset token generated for username {username}.")
            return redirect(url_for('reset_password_token', token=reset_token))
        return render_template('auth/change_password.html')

    @app.route('/reset_password/<token>', methods=['GET', 'POST'])
    @login_required
    def reset_password_token(token):
        user = User.verify_reset_token(token)
        if not user:
            flash('Invalid or expired token', 'danger')
            current_app.logger.debug(f"Password reset token invalid or expired.")
            return redirect(url_for('reset_password'))
        if request.method == 'POST':
            password = request.form['password']
            user.set_password(password)
            db.session.commit()
            flash('Your password has been updated!', 'success')
            current_app.logger.debug(f"Password updated for username {user.username}.")
            return redirect(url_for('login'))
        return render_template('auth/reset_password_token.html')

    @app.route('/login/telegram', methods=['GET', 'POST'])
    def login_telegram():
        if request.method == 'POST':
            phone_number = request.form['phone']
            session['phone_number'] = phone_number  # Сохраняем номер телефона в сессии

            client = TelegramClient('session_name', Config.TELEGRAM_API_ID, Config.TELEGRAM_API_HASH)
            client.connect()

            if not client.is_user_authorized():
                client.send_code_request(phone_number)
                session['client'] = client.session.save()  # Сохраняем сессию клиента

                return redirect(url_for('enter_telegram_code'))  # Перенаправляем на страницу ввода кода

        return render_template('auth/login_telegram.html')

    @app.route('/login/telegram/code', methods=['GET', 'POST'])
    def enter_telegram_code():
        if request.method == 'POST':
            code = request.form['code']
            client = TelegramClient('session_name', Config.TELEGRAM_API_ID, Config.TELEGRAM_API_HASH)
            client.connect()
            client.session.load(session['client'])

            try:
                client.sign_in(session['phone_number'], code)

                user_info = client.get_me()
                user = User.query.filter_by(telegram_id=user_info.id).first()

                if not user:
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
                return redirect(url_for('index'))

            except Exception as e:
                flash('Failed to authenticate via Telegram. Please check the code and try again.', 'danger')
                return redirect(url_for('login_telegram'))

        return render_template('auth/enter_telegram_code.html')

    @app.route('/login/vk')
    def login_vk():
        state = 'dePbvCFsCkaixThxcVMOqs1K0WVEUtTI'
        session['state'] = state
        session['code_verifier'] = generate_code_verifier()

        vk_auth_url = (
                'https://id.vk.com/authorize'
                '?response_type=code'
                '&client_id=' + Config.VK_CLIENT_ID +
                '&scope=email phone'
                '&redirect_uri=' + url_for('authorize_vk', _external=True) +
                '&state=' + state +
                '&code_challenge=' + generate_code_challenge(session['code_verifier']) +
                '&code_challenge_method=s256'
        )

        current_app.logger.debug(f"VK login initiated. Redirecting to VK Auth URL: {vk_auth_url}")
        return redirect(vk_auth_url)

    @app.route('/vk/callback')
    def authorize_vk():
        code = request.args.get('code')
        state = request.args.get('state')
        device_id = request.args.get('device_id')

        if state != session.get('state'):
            flash('State mismatch. Authorization failed.', 'danger')
            current_app.logger.debug(f"State mismatch during VK callback. Expected {session.get('state')}, got {state}.")
            session.clear()
            return redirect(url_for('login'))

        if not device_id:
            flash('Device ID is missing in the callback response.', 'danger')
            current_app.logger.debug("Device ID is missing in the callback response.")
            return redirect(url_for('login'))

        session['device_id'] = device_id
        current_app.logger.debug(f"Received device ID: {device_id}")

        data = {
            'client_id': Config.VK_CLIENT_ID,
            'grant_type': 'authorization_code',
            'code_verifier': session.get('code_verifier'),
            'code': code,
            'device_id': device_id,
            'redirect_uri': url_for('authorize_vk', _external=True),
        }

        current_app.logger.debug(f"Exchanging VK code for tokens. Data: {data}")
        response = requests.post('https://id.vk.com/oauth2/auth', data=data)
        tokens = response.json()

        if 'access_token' not in tokens:
            flash('Failed to retrieve access token.', 'danger')
            current_app.logger.debug(f"Failed to retrieve tokens from VK. Response: {tokens}")
            session.clear()
            return redirect(url_for('login'))

        access_token = tokens['access_token']
        refresh_token = tokens.get('refresh_token')

        user_info_response = requests.post('https://id.vk.com/oauth2/user_info', data={
            'access_token': access_token,
            'client_id': Config.VK_CLIENT_ID
        })
        user_info = user_info_response.json()

        if not user_info or 'user' not in user_info:
            flash('Failed to retrieve user info from VK.', 'danger')
            current_app.logger.debug(f"Failed to retrieve user info. Response: {user_info}")
            return redirect(url_for('login'))

        vk_id = user_info['user']['user_id']
        first_name = user_info['user']['first_name']
        last_name = user_info['user']['last_name']
        email = user_info['user']['email']

        user = User.query.filter_by(vk_id=vk_id).first()

        if not user:
            user = User(
                username=email.split('@')[0],
                vk_id=vk_id,
                first_name=first_name,
                last_name=last_name,
                email=email,
                device_id=device_id,
                access_token=access_token,
                refresh_token=refresh_token
            )
            db.session.add(user)
            current_app.logger.debug(f"Created new VK user with ID: {vk_id}")

        else:
            user.device_id = device_id
            user.access_token = access_token
            user.refresh_token = refresh_token
            user.first_name = first_name
            user.last_name = last_name
            user.email = email

            db.session.add(user)

        db.session.commit()

        authenticate_vk_user(vk_id, email.split('@')[0], first_name, last_name, email)

        flash(f'Successfully logged in as {first_name} {last_name}', 'success')
        current_app.logger.debug(f"User {first_name} {last_name} authenticated and logged in.")
        return redirect(url_for('index'))

    def refresh_vk_token(refresh_token):
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': Config.VK_CLIENT_ID,
            'device_id': session.get('device_id'),
            'state': 'dePbvCFsCkaixThxcVMOqs1K0WVEUtTI'
        }

        response = requests.post('https://id.vk.com/oauth2/auth', data=data)
        tokens = response.json()

        if 'access_token' not in tokens:
            flash('Failed to refresh access token.', 'danger')
            current_app.logger.debug(f"Failed to refresh access token. Response: {tokens}")
            return None

        session['access_token'] = tokens['access_token']
        current_app.logger.debug(f"Access token refreshed. New Access Token: {tokens['access_token']}")
        return tokens

    def logout_vk():
        access_token = session.get('access_token')

        if not access_token:
            flash('Failed to logout: Missing access token.', 'danger')
            current_app.logger.debug(f"Failed to logout from VK. Missing access token.")
            return

        data = {
            'client_id': Config.VK_CLIENT_ID,
            'access_token': access_token
        }

        current_app.logger.debug(f"Logging out from VK. Data: {data}")
        response = requests.post('https://id.vk.com/oauth2/logout', data=data)

        if response.json().get('response') == 1:
            flash('Successfully logged out of VK.', 'success')
            current_app.logger.debug(f"Successfully logged out of VK.")
        else:
            flash('Failed to log out of VK.', 'danger')
            current_app.logger.debug(f"Failed to log out of VK. Response: {response.json()}")

        # Очистка данных сессии
        session.pop('access_token', None)
        session.pop('device_id', None)

    @app.route('/logout')
    @login_required
    def logout():
        try:
            current_app.logger.debug("Initiating VK logout.")
            logout_vk()
        except Exception as e:
            current_app.logger.error(f"VK logout failed: {e}")

        try:
            current_app.logger.debug("Logging out user.")
            logout_user()
        except Exception as e:
            current_app.logger.error(f"User logout failed: {e}")

        try:
            current_app.logger.debug("Clearing session data.")
            session.clear()
        except Exception as e:
            current_app.logger.error(f"Session clearing failed: {e}")

        current_app.logger.debug(f"User logged out successfully.")
        return redirect(url_for('index'))
