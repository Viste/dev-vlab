from flask_admin.contrib.sqla import ModelView
from database.models import BlogPost, Project, NavigationLink


def setup_admin(admin, db):
    admin.add_view(ModelView(BlogPost, db.session))
    admin.add_view(ModelView(Project, db.session))
    admin.add_view(ModelView(NavigationLink, db.session))
