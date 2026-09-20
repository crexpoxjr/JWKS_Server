import pytest
from app import app, KEYS_DB

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_jwk_endpoint(client):
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = response.get_json()

    # Verify only unexpired key is served
    assert "keys" in data
    kids = [key["kid"] for key in data["keys"]]
    assert "valid-kid-1" in kids
    assert "expired-kid-1" not in kids

def test_auth_endpoints_valid(client):
    response = client.post('/auth')
    assert response.status_code == 200
    token = response.data.decode('utf-8')
    assert token is not None

def test_auth_endpoints_expired(client):
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    token = response.data.decode('utf-8')
    assert token is not None
    