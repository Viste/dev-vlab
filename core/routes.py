from authlib.integrations.flask_client import OAuth
from flask import render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user

from database.models import db, Project, BlogPost, NavigationLink, User, Comment
from tools.config import Config

oauth = OAuth()


def setup_routes(app):
    # Настройка OAuth для VK
    oauth.init_app(app)
    vk = oauth.register(
        name='vk',
        client_id=Config.VK_CLIENT_ID,
        client_secret=Config.VK_CLIENT_SECRET,
        authorize_url='https://oauth.vk.com/authorize',
        access_token_url='https://oauth.vk.com/access_token',
        redirect_uri=url_for('authorize_vk', _external=True),
        client_kwargs={'scope': 'email'}
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
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('index'))
            else:
                flash('Login Unsuccessful. Please check username and password', 'danger')
        return render_template('auth/login.html')

    @app.route('/login/vk')
    def login_vk():
        redirect_uri = url_for('authorize_vk', _external=True)
        return vk.authorize_redirect(redirect_uri)

    @app.route('/vk/callback')
    def authorize_vk():
        try:
            token = vk.authorize_access_token()
            resp = vk.get(
                'https://api.vk.com/method/users.get',
                token=token,
                params={
                    'v': '5.131',
                    'fields': 'id,first_name,last_name,screen_name,photo_100,email'
                }
            )
            profile = resp.json()['response'][0]

            vk_id = profile['id']
            first_name = profile['first_name']
            last_name = profile['last_name']
            screen_name = profile.get('screen_name', f'vk_{vk_id}')
            profile_picture = profile.get('photo_100', '')
            email = token.get('email')

            user = User.query.filter_by(vk_id=vk_id).first()
            if not user:
                user = User(username=screen_name, vk_id=vk_id, first_name=first_name, last_name=last_name,
                            profile_picture=profile_picture, email=email, provider='vk')
                db.session.add(user)
                db.session.commit()
            login_user(user)
            return redirect(url_for('index'))
        except Exception as e:
            flash('Authorization failed. Please try again.', 'danger')
            return redirect(url_for('login'))

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('index'))