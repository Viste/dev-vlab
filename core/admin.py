import flask_admin as admin
from flask import redirect, url_for, request, session
from flask_admin import AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_login import login_user, logout_user, current_user, login_required

from database.models import BlogPost, Project, NavigationLink, User
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
    return admin
