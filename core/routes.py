from authlib.integrations.flask_client import OAuth
from flask import render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_user, logout_user, login_required, current_user

from database.models import db, Project, BlogPost, NavigationLink, User, Comment
from tools.auth import authenticate_vk_user, authenticate_user
from tools.config import Config

oauth = OAuth()

def setup_routes(app):
    oauth.init_app(app)
    vk = oauth.register(
        name='vk',
        client_id=Config.VK_CLIENT_ID,
        client_secret=Config.VK_CLIENT_SECRET,
        authorize_url='https://id.vk.com/auth',
        access_token_url='https://id.vk.com/token',
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
                return redirect(next_page) if next_page else redirect(url_for('index'))
            else:
                flash('Login Unsuccessful. Please check username and password', 'danger')

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
        else:
            user = User(telegram_id=telegram_id, username=username, first_name=first_name, last_name=last_name, profile_picture=profile_picture, provider='telegram')
            db.session.add(user)

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
                return redirect(url_for('register'))
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('index'))
        return render_template('auth/register.html')

    @app.route('/reset_password', methods=['GET', 'POST'])
    def reset_password():
        if request.method == 'POST':
            username = request.form['username']
            user = User.query.filter_by(username=username).first()
            if not user:
                flash('No account found with that username.', 'danger')
                return redirect(url_for('reset_password'))
            reset_token = user.get_reset_token()
            return redirect(url_for('reset_password_token', token=reset_token))
        return render_template('auth/change_password.html')

    @app.route('/reset_password/<token>', methods=['GET', 'POST'])
    def reset_password_token(token):
        user = User.verify_reset_token(token)
        if not user:
            flash('Invalid or expired token', 'danger')
            return redirect(url_for('reset_password'))
        if request.method == 'POST':
            password = request.form['password']
            user.set_password(password)
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('login'))
        return render_template('auth/reset_password_token.html')

    @app.route('/login/vk')
    def login_vk():
        redirect_uri = url_for('authorize_vk', _external=True)
        return vk.authorize_redirect(redirect_uri)

    @app.route('/vk/callback')
    def authorize_vk():
        try:
            token = vk.authorize_access_token()
            if not token:
                flash('Failed to retrieve token from VK', 'danger')
                return redirect(url_for('login'))

            print(f'Token: {token}')

            access_token = token.get('access_token')
            if not access_token:
                flash('Access token is missing in the VK response', 'danger')
                return redirect(url_for('login'))

            resp = vk.get(
                'https://api.vk.com/method/users.get',
                params={
                    'access_token': access_token,
                    'v': '5.131',
                    'fields': 'id,first_name,last_name,screen_name,photo_100,email'
                }
            )

            print(f'Response from VK: {resp.json()}')

            profile = resp.json().get('response', [])[0]
            if not profile:
                flash('Failed to retrieve user profile from VK', 'danger')
                return redirect(url_for('login'))

            vk_id = profile['id']
            first_name = profile['first_name']
            last_name = profile['last_name']
            screen_name = profile.get('screen_name', f'vk_{vk_id}')
            profile_picture = profile.get('photo_100', '')
            email = token.get('email')

            authenticate_vk_user(vk_id, screen_name, first_name, last_name, profile_picture, email)

            flash(f'Successfully logged in as {screen_name}', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            print(f'Error during VK authorization: {e}')
            flash('Authorization failed. Please try again.', 'danger')
            return redirect(url_for('login'))

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('index'))