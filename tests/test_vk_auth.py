from unittest.mock import patch

import pytest

from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            yield client


def test_login_vk_redirect(client):
    response = client.get('/login/vk')
    assert response.status_code == 302


@patch('app.oauth.vk.authorize_access_token')
@patch('app.oauth.vk.get')
def test_authorize_vk_success(mock_get, mock_authorize_access_token, client):
    mock_authorize_access_token.return_value = {
        'access_token': 'mock_access_token',
        'email': 'user@example.com'
    }

    mock_get.return_value.json.return_value = {
        'response': [{
            'id': 12345,
            'first_name': 'John',
            'last_name': 'Doe',
            'screen_name': 'john_doe',
            'photo_100': 'http://example.com/photo.jpg'
        }]
    }

    with patch('tools.auth.authenticate_vk_user') as mock_authenticate:
        response = client.get('/vk/callback')

        assert response.status_code == 302  # Redirects after successful login
        assert mock_authenticate.called_once_with(
            12345, 'john_doe', 'John', 'Doe', 'http://example.com/photo.jpg', 'user@example.com'
        )


@patch('app.oauth.vk.authorize_access_token')
def test_authorize_vk_no_token(mock_authorize_access_token, client):
    mock_authorize_access_token.return_value = None

    response = client.get('/vk/callback')

    assert response.status_code == 302
    assert b'login' in response.location


@patch('app.oauth.vk.authorize_access_token')
@patch('app.oauth.vk.get')
def test_authorize_vk_profile_failure(mock_get, mock_authorize_access_token, client):
    mock_authorize_access_token.return_value = {
        'access_token': 'mock_access_token',
        'email': 'user@example.com'
    }

    mock_get.return_value.json.return_value = {'response': []}

    response = client.get('/vk/callback')

    assert response.status_code == 302
    assert b'login' in response.location