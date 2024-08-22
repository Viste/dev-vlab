from unittest.mock import patch

import pytest
from flask import url_for

from app import app, db
from database.models import User, BlogPost, Comment


@pytest.fixture(autouse=True)
def mock_bot():
    with patch("core.routes.bot"):
        yield


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


@pytest.fixture
def new_user():
    user = User(username='testuser', email='test@example.com')
    user.set_password('password')
    return user


@pytest.fixture
def login_user(client, new_user):
    db.session.add(new_user)
    db.session.commit()
    client.post('/login', data={'username': new_user.username, 'password': 'password'})
    return new_user


def test_index(client):
    response = client.get(url_for('index'))
    assert response.status_code == 200
    assert b'Viste' in response.data


def test_profile(client, login_user):
    response = client.get(url_for('profile'))
    assert response.status_code == 200
    assert b'testuser' in response.data


def test_blog(client):
    response = client.get(url_for('blog'))
    assert response.status_code == 200
    assert b'Blog' in response.data


def test_view_post(client, login_user):
    post = BlogPost(title='Test Post', content='Test Content')
    db.session.add(post)
    db.session.commit()

    response = client.get(url_for('view_post', post_id=post.id))
    assert response.status_code == 200
    assert b'Test Post' in response.data


def test_add_comment(client, login_user):
    post = BlogPost(title='Test Post', content='Test Content')
    db.session.add(post)
    db.session.commit()

    response = client.post(url_for('add_comment', post_id=post.id), data={'comment': 'Nice post!'})
    assert response.status_code == 302  # редирект после добавления комментария

    comment = Comment.query.filter_by(content='Nice post!').first()
    assert comment is not None
    assert comment.post_id == post.id


def test_login(client):
    response = client.post('/login', data={'username': 'testuser', 'password': 'password'})
    assert response.status_code == 302  # редирект после успешного логина


def test_register(client):
    response = client.post('/register', data={'username': 'newuser', 'password': 'newpassword'})
    assert response.status_code == 302  # редирект после успешной регистрации

    user = User.query.filter_by(username='newuser').first()
    assert user is not None


def test_reset_password(client, login_user):
    response = client.post(url_for('reset_password'), data={'username': login_user.username})
    assert response.status_code == 302  # редирект после запроса сброса пароля


def test_logout(client, login_user):
    response = client.get(url_for('logout'))
    assert response.status_code == 302  # редирект после успешного выхода
