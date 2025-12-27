import os

from provity.db import get_database_url, get_database_url_readonly


def test_get_database_url_defaults_when_env_missing(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert get_database_url().startswith("postgresql://")


def test_get_database_url_readonly_precedence(monkeypatch):
    monkeypatch.setenv("DATABASE_URL_READONLY", "postgresql://ro")
    monkeypatch.setenv("DATABASE_URL", "postgresql://rw")
    assert get_database_url_readonly() == "postgresql://ro"

    monkeypatch.delenv("DATABASE_URL_READONLY", raising=False)
    assert get_database_url_readonly() == "postgresql://rw"
