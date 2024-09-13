import os

import flask_admin as admin
from flask import redirect, url_for, request, session, flash
from flask_admin import AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.utils import secure_filename

from database.models import BlogPost, Project, NavigationLink, User, MusicRelease, MusicDemo, db
from tools.config import Config
from tools.forms import LoginForm


class MyModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def is_admin(self):
        return current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))


class MyAdminIndexView(AdminIndexView):
    @admin.expose('/')
    @login_required
    def index(self):
        if not current_user.is_authenticated:
            return redirect(url_for('admin.login_view'))
        return super(MyAdminIndexView, self).index()

    @admin.expose('/admin_login/', methods=('GET', 'POST'))
    def login_view(self):
        form = LoginForm(request.form)
        if admin.helpers.validate_form_on_submit(form):
            user = form.get_user()
            login_user(user)

        if current_user.is_authenticated:
            return redirect(url_for('admin.index'))
        self._template_args['form'] = form
        return super(MyAdminIndexView, self).render('admin/login.html')

    @admin.expose('/upload_demo', methods=['POST'])
    @login_required
    def upload_demo(self):
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
            file.save(file_path)

            new_demo = MusicDemo(title=request.form['title'], file_url=file_path)
            db.session.add(new_demo)
            db.session.commit()

            return redirect(url_for('music'))

    @admin.expose('/admin_logout/')
    def logout_view(self):
        logout_user()
        session.clear()
        return redirect(url_for('admin.login_view'))


def setup_admin(app, db):
    admins = admin.Admin(app, name='Admin Panel', template_mode='bootstrap4', index_view=MyAdminIndexView())
    admins.add_view(MyModelView(BlogPost, db.session))
    admins.add_view(MyModelView(Project, db.session))
    admins.add_view(MyModelView(NavigationLink, db.session))
    admins.add_view(MyModelView(User, db.session))
    admins.add_view(ModelView(MusicRelease, db.session))
    admins.add_view(ModelView(MusicDemo, db.session))
    return admin
