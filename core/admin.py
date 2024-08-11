from flask import redirect, url_for, request
from flask_admin import Admin
from flask_admin import AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, current_user

from database.models import User, BlogPost, Project, NavigationLink

login_manager = LoginManager()


class MyModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))


class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        return super(MyAdminIndexView, self).index()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def setup_admin(app, db):
    admin = Admin(app, name='Admin Panel', template_mode='bootstrap4', index_view=MyAdminIndexView())
    admin.add_view(MyModelView(BlogPost, db.session))
    admin.add_view(MyModelView(Project, db.session))
    admin.add_view(MyModelView(NavigationLink, db.session))
    return admin
