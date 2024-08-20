import logging

import requests
from flask import render_template, redirect, url_for, request, flash, jsonify, session, current_app
from flask_login import login_user, logout_user, login_required, current_user

from database.models import db, Project, BlogPost, NavigationLink, User, Comment
from tools.auth import authenticate_vk_user, authenticate_user
from tools.config import Config
from tools.utils import generate_code_verifier, generate_code_challenge

logging.basicConfig(level=logging.DEBUG)


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
        return render_template('profile.html', user=current_user)

    @app.route('/blog')
    def blog():
        posts = BlogPost.query.all()
        return render_template('blog/blog.html', posts=posts)

    @app.route('/blog/<int:post_id>')
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

    @app.route('/update_telegram_profile', methods=['POST'])
    def update_telegram_profile():
        data = request.json
        telegram_id = data.get('telegram_id')
        username = data.get('username')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        profile_picture = data.get('profile_picture')

        user = User.query.filter_by(telegram_id=telegram_id).first()
        if user:
            user.username = username
            user.first_name = first_name
            user.last_name = last_name
            user.profile_picture = profile_picture
            current_app.logger.debug(f"Updated Telegram profile for user {username}.")
        else:
            user = User(telegram_id=telegram_id, username=username, first_name=first_name, last_name=last_name, profile_picture=profile_picture, provider='telegram')
            db.session.add(user)
            current_app.logger.debug(f"Created new Telegram user {username}.")

        db.session.commit()
        return jsonify({"status": "success"}), 200

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

        if state != session.get('state'):
            flash('State mismatch. Authorization failed.', 'danger')
            current_app.logger.debug(f"State mismatch during VK callback. Expected {session.get('state')}, got {state}.")
            return redirect(url_for('login'))

        data = {
            'client_id': Config.VK_CLIENT_ID,
            'grant_type': 'authorization_code',
            'code_verifier': session['code_verifier'],
            'code': code,
            'redirect_uri': url_for('authorize_vk', _external=True),
            'device_id': session.get('device_id')
        }

        current_app.logger.debug(f"Exchanging VK code for tokens. Data: {data}")
        response = requests.post('https://id.vk.com/oauth2/auth', data=data)
        tokens = response.json()

        if 'access_token' not in tokens or 'device_id' not in tokens:
            flash('Failed to retrieve access token or device ID', 'danger')
            current_app.logger.debug(f"Failed to retrieve tokens from VK. Response: {tokens}")
            return redirect(url_for('login'))

        # Сохранение access_token и device_id в сессии или базе данных
        access_token = tokens['access_token']
        device_id = tokens['device_id']
        session['device_id'] = device_id
        session['access_token'] = access_token
        current_app.logger.debug(f"Tokens received. Access Token: {access_token}, Device ID: {device_id}")

        # Получение данных пользователя
        user_info = requests.post('https://id.vk.com/oauth2/user_info', data={
            'access_token': access_token,
            'client_id': Config.VK_CLIENT_ID
        }).json()

        user_id = user_info['user']['user_id']
        first_name = user_info['user']['first_name']
        last_name = user_info['user']['last_name']
        email = user_info['user']['email']

        current_app.logger.debug(f"User info received from VK. User ID: {user_id}, Name: {first_name} {last_name}")

        authenticate_vk_user(user_id, first_name, last_name, email)

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

        # Сохранение нового access_token
        session['access_token'] = tokens['access_token']
        current_app.logger.debug(f"Access token refreshed. New Access Token: {tokens['access_token']}")
        return tokens

    def logout_vk():
        access_token = session.get('access_token')
        device_id = session.get('device_id')

        if not access_token or not device_id:
            flash('Failed to logout: Missing access token or device ID.', 'danger')
            current_app.logger.debug(f"Failed to logout from VK. Missing access token or device ID.")
            return redirect(url_for('index'))

        data = {
            'client_id': Config.VK_CLIENT_ID,
            'access_token': access_token,
            'device_id': device_id
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

        return response.json()

    @app.route('/logout')
    @login_required
    def logout():
        logout_vk()
        logout_user()
        current_app.logger.debug(f"User logged out successfully.")
        return redirect(url_for('index'))
