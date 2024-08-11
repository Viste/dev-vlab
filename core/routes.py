from flask import render_template
from database.models import Project, NavigationLink, BlogPost


def setup_routes(app):
    @app.route('/')
    def index():
        projects = Project.query.all()
        links = NavigationLink.query.all()
        return render_template('index.html', nick="Viste", projects=projects, links=links)

    @app.route('/blog')
    def blog():
        posts = BlogPost.query.all()
        return render_template('blog.html', posts=posts)
