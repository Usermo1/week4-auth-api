from security import hash_password, verify_password

USER = {"username": "student", "email": "student@example.com", "password": "secret123"}


def test_password_hash():
    hashed = hash_password(USER["password"])
    assert hashed != USER["password"]
    assert verify_password(USER["password"], hashed)
    assert not verify_password("wrong", hashed)


def test_login_and_profile(client):
    registered = client.post("/auth/register", json=USER)
    assert registered.status_code == 201
    assert set(registered.json()) == {"id", "username", "email"}
    login = client.post("/auth/login", json=USER)
    assert login.status_code == 200
    token = login.json()["access_token"]
    profile = client.get("/profile/me", headers={"Authorization": f"Bearer {token}"})
    assert profile.status_code == 200
    assert profile.json() == registered.json()


def test_profile_requires_token(client):
    response = client.get("/profile/me")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}

def test_duplicate_registration(client):
    registered = client.post("/auth/register", json=USER)
    assert registered.status_code == 201
    duplicate = client.post("/auth/register", json=USER)
    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "Email already registered"}

def test_wrong_password_login(client):
    registered = client.post("/auth/register", json=USER)
    assert registered.status_code == 201
    wrong_password = {**USER, "password": "wrong"}
    login = client.post("/auth/login", json=wrong_password)
    assert login.status_code == 401
    assert login.json() == {"detail": "Invalid email or password"}

def test_invalid_registration_data(client):
    invalid_user = {"username": "student", "email": "not-an-email", "password": "short"}
    response = client.post("/auth/register", json=invalid_user)
    assert response.status_code == 422  # Unprocessable Entity
    errors = response.json()["detail"]
    assert any(error["loc"][-1] == "email" for error in errors)
    assert any(error["loc"][-1] == "password" for error in errors)