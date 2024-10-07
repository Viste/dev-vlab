import os

import flask_admin as admin
from flask import redirect, url_for, request, flash, session
from flask_admin import BaseView, expose, AdminIndexView
from flask_login import current_user, login_user, logout_user
from werkzeug.utils import secure_filename

from database.models import BlogPost, Project, NavigationLink, MusicRelease, MusicDemo, db
from tools.config import Config
from tools.forms import BlogPostForm, ProjectForm, NavigationLinkForm, MusicReleaseForm, MusicDemoForm, LoginForm


class CustomBaseView(BaseView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin.login_view'))


class BlogPostView(CustomBaseView):
    @expose('/')
    def index(self):
        posts = BlogPost.query.all()
        return self.render('admin/blog_posts.html', posts=posts)

    @expose('/new', methods=['GET', 'POST'])
    def create(self):
        form = BlogPostForm(request.form)
        if request.method == 'POST' and form.validate():
            new_post = BlogPost(title=form.title.data, content=form.content.data)
            db.session.add(new_post)
            db.session.commit()
            flash('Blog post created successfully!')
            return redirect(url_for('blogpostview.index'))
        return self.render('admin/blog_post_form.html', form=form)


class ProjectView(CustomBaseView):
    @expose('/')
    def index(self):
        projects = Project.query.all()
        return self.render('admin/projects.html', projects=projects)

    @expose('/new', methods=['GET', 'POST'])
    def create(self):
        form = ProjectForm(request.form)
        if request.method == 'POST' and form.validate():
            new_project = Project(name=form.name.data, image_url=form.image_url.data, url=form.url.data)
            db.session.add(new_project)
            db.session.commit()
            flash('Project created successfully!')
            return redirect(url_for('projectview.index'))
        return self.render('admin/project_form.html', form=form)


class NavigationLinkView(CustomBaseView):
    @expose('/')
    def index(self):
        links = NavigationLink.query.all()
        return self.render('admin/navigation_links.html', links=links)

    @expose('/new', methods=['GET', 'POST'])
    def create(self):
        form = NavigationLinkForm(request.form)
        if request.method == 'POST' and form.validate():
            new_link = NavigationLink(title=form.title.data, url=form.url.data)
            db.session.add(new_link)
            db.session.commit()
            flash('Navigation link created successfully!')
            return redirect(url_for('navigationlinkview.index'))
        return self.render('admin/navigation_link_form.html', form=form)


class MusicReleaseView(CustomBaseView):
    @expose('/')
    def index(self):
        releases = MusicRelease.query.all()
        return self.render('admin/music_releases.html', releases=releases)

    @expose('/new', methods=['GET', 'POST'])
    def create(self):
        form = MusicReleaseForm(request.form)
        if request.method == 'POST' and form.validate():
            new_release = MusicRelease(title=form.title.data, release_url=form.release_url.data)
            db.session.add(new_release)
            db.session.commit()
            flash('Music release created successfully!')
            return redirect(url_for('musicreleaseview.index'))
        return self.render('admin/music_release_form.html', form=form)


class MusicDemoView(CustomBaseView):
    @expose('/')
    def index(self):
        demos = MusicDemo.query.all()
        return self.render('admin/music_demos.html', demos=demos)

    @expose('/upload', methods=['GET', 'POST'])
    def upload(self):
        form = MusicDemoForm(request.form)
        if request.method == 'POST' and form.validate():
            file = form.file.data
            filename = secure_filename(file.filename)
            file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
            file.save(file_path)

            new_demo = MusicDemo(title=form.title.data, file_url=file_path)
            db.session.add(new_demo)
            db.session.commit()
            flash('Music demo uploaded successfully!')
            return redirect(url_for('musicdemoview.index'))
        return self.render('admin/music_demo_form.html', form=form)


class DashboardView(AdminIndexView):
    @expose('/')
    def index(self):
        if not current_user.is_authenticated:
            return redirect(url_for('admin.login_view'))
        return self.render('admin/dashboard.html')

    @expose('/admin_login/', methods=('GET', 'POST'))
    def login_view(self):
        form = LoginForm(request.form)
        if form.validate_login():
            user = form.get_user()
            login_user(user)
            return redirect(url_for('admin.index'))

        if current_user.is_authenticated:
            return redirect(url_for('admin.index'))

        return self.render('admin/login.html', form=form)

    @expose('/admin_logout/')
    def logout_view(self):
        logout_user()
        session.clear()
        return redirect(url_for('admin.login_view'))

def setup_admin(app):
    admins = admin.Admin(app, name='Admin Panel', template_mode='bootstrap4', index_view=DashboardView())
    admins.add_view(BlogPostView(name='Manage Blog Posts', endpoint='blogpostview'))
    admins.add_view(ProjectView(name='Manage Projects', endpoint='projectview'))
    admins.add_view(NavigationLinkView(name='Manage Navigation Links', endpoint='navigationlinkview'))
    admins.add_view(MusicReleaseView(name='Manage Music Releases', endpoint='musicreleaseview'))
    admins.add_view(MusicDemoView(name='Upload Music Demos', endpoint='musicdemoview'))
    return admins
