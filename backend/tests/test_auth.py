"""Authentication endpoint tests covering register / login / me / token expiry."""

from __future__ import annotations

from datetime import timedelta

import pytest

from core.security import create_access_token


@pytest.mark.asyncio
async def test_register_creates_user(client) -> None:
    """A fresh email + valid password should yield a 201 with a JWT."""
    response = await client.post(
        "/api/auth/register",
        json={
            "email": "newuser@example.com",
            "password": "StrongPass123!",
            "name": "New User",
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["access_token"]
    assert body["token_type"] == "bearer"
    assert body["user"]["email"] == "newuser@example.com"
    assert body["user"]["name"] == "New User"
    assert body["user"]["is_active"] is True


@pytest.mark.asyncio
async def test_register_duplicate_email_rejected(client) -> None:
    """Registering the same email twice should 409."""
    payload = {
        "email": "dup@example.com",
        "password": "StrongPass123!",
        "name": "Dup",
    }
    first = await client.post("/api/auth/register", json=payload)
    assert first.status_code == 201

    second = await client.post("/api/auth/register", json=payload)
    assert second.status_code == 409
    assert "already registered" in second.json()["detail"].lower()


@pytest.mark.asyncio
async def test_register_short_password_rejected(client) -> None:
    """Passwords shorter than 8 chars must be rejected with 422."""
    response = await client.post(
        "/api/auth/register",
        json={
            "email": "shortpw@example.com",
            "password": "abc",
            "name": "Short PW",
        },
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_login_returns_token(client) -> None:
    """A registered user should be able to log in and receive a token."""
    register = await client.post(
        "/api/auth/register",
        json={
            "email": "loginuser@example.com",
            "password": "StrongPass123!",
            "name": "Login User",
        },
    )
    assert register.status_code == 201

    response = await client.post(
        "/api/auth/login",
        json={
            "email": "loginuser@example.com",
            "password": "StrongPass123!",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["user"]["email"] == "loginuser@example.com"


@pytest.mark.asyncio
async def test_login_wrong_password_returns_401(client) -> None:
    """Logging in with a wrong password should return 401."""
    register = await client.post(
        "/api/auth/register",
        json={
            "email": "wrongpw@example.com",
            "password": "StrongPass123!",
            "name": "Wrong PW",
        },
    )
    assert register.status_code == 201

    response = await client.post(
        "/api/auth/login",
        json={
            "email": "wrongpw@example.com",
            "password": "WrongPassword!",
        },
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_me_requires_token(client) -> None:
    """Calling /api/auth/me without a token should be rejected."""
    response = await client.get("/api/auth/me")
    # FastAPI's HTTPBearer returns 403 by default when no creds are supplied.
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_get_me_with_token_returns_user(client, test_user) -> None:
    """Calling /api/auth/me with a valid bearer token returns the user."""
    response = await client.get("/api/auth/me", headers=test_user["headers"])
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == test_user["user"].email
    assert body["id"] == str(test_user["user"].id)


@pytest.mark.asyncio
async def test_expired_token_returns_401(client, test_user) -> None:
    """A JWT past its ``exp`` claim must be rejected with 401."""
    expired = create_access_token(
        data={"sub": str(test_user["user"].id), "email": test_user["user"].email},
        expires_delta=timedelta(seconds=-3600),
    )
    response = await client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {expired}"},
    )
    assert response.status_code == 401
