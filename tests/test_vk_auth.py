from unittest.mock import patch, MagicMock

import pytest

from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            yield client


@patch('app.setup_routes')
def test_authorize_vk_success(mock_setup_routes, client):
    mock_oauth = MagicMock()
    mock_vk = mock_oauth.register.return_value
    mock_setup_routes.side_effect = lambda app, oauth: oauth
    app.oauth = mock_oauth

    mock_vk.authorize_access_token.return_value = {
        'access_token': 'mock_access_token',
        'email': 'user@example.com'
    }
    mock_vk.get.return_value.json.return_value = {
        'response': [{
            'id': 12345,
            'first_name': 'John',
            'last_name': 'Doe',
            'screen_name': 'john_doe',
            'photo_100': 'https://i.pinimg.com/736x/90/bd/09/90bd09bc51dba0bd127db954591d3650.jpg'
        }]
    }

    with patch('tools.auth.authenticate_vk_user') as mock_authenticate:
        response = client.get('/vk/callback')
        assert response.status_code == 302  # Redirects after successful login
        assert mock_authenticate.called_once_with(
            12345, 'john_doe', 'John', 'Doe', 'https://i.pinimg.com/736x/90/bd/09/90bd09bc51dba0bd127db954591d3650.jpg', 'user@example.com'
        )


@patch('app.setup_routes')
def test_authorize_vk_no_token(mock_setup_routes, client):
    mock_oauth = MagicMock()
    mock_vk = mock_oauth.register.return_value
    mock_setup_routes.side_effect = lambda app, oauth: oauth
    app.oauth = mock_oauth

    mock_vk.authorize_access_token.return_value = None  # Simulate a failed token retrieval

    response = client.get('/vk/callback')

    assert response.status_code == 302
    assert b'login' in response.location


@patch('app.setup_routes')
def test_authorize_vk_profile_failure(mock_setup_routes, client):
    mock_oauth = MagicMock()
    mock_vk = mock_oauth.register.return_value
    mock_setup_routes.side_effect = lambda app, oauth: oauth
    app.oauth = mock_oauth

    mock_vk.authorize_access_token.return_value = {
        'access_token': 'mock_access_token',
        'email': 'user@example.com'
    }
    mock_vk.get.return_value.json.return_value = {'response': []}

    response = client.get('/vk/callback')

    assert response.status_code == 302
    assert b'login' in response.location
