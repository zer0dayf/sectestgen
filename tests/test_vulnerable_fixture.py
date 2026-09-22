"""Proves each vulnerable endpoint in the fixture is actually exploitable and
each safe counterpart actually blocks the same attack. This is the ground
truth the WP1 static/reachability adapters will later be scored against.
"""

import base64
import pickle
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from fixtures.vulnerable_fastapi.app import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


# --- CWE-78: OS command injection -------------------------------------------


def test_ping_command_injection_executes_extra_command(client, tmp_path):
    marker = tmp_path / "pwned_cmd"
    host = f"127.0.0.1; touch {marker}"

    client.get(f"/ping/{quote(host, safe='/')}")

    assert marker.exists()


def test_ping_safe_rejects_non_ip_host(client, tmp_path):
    marker = tmp_path / "pwned_cmd_safe"
    host = f"127.0.0.1; touch {marker}"

    response = client.get(f"/ping-safe/{quote(host, safe='/')}")

    assert response.status_code == 400
    assert not marker.exists()


# --- CWE-95: dynamic evaluation ----------------------------------------------


def test_calc_eval_executes_arbitrary_code(client, tmp_path):
    marker = tmp_path / "pwned_eval"
    expression = f"__import__('pathlib').Path(r'{marker}').touch() or 1"

    client.post("/calc", json={"expression": expression})

    assert marker.exists()


def test_calc_safe_rejects_non_arithmetic_expression(client, tmp_path):
    marker = tmp_path / "pwned_eval_safe"
    expression = f"__import__('pathlib').Path(r'{marker}').touch() or 1"

    response = client.post("/calc-safe", json={"expression": expression})

    assert response.status_code == 400
    assert not marker.exists()


def test_calc_safe_allows_plain_arithmetic(client):
    response = client.post("/calc-safe", json={"expression": "2 + 3 * 4"})

    assert response.status_code == 200
    assert response.json()["result"] == 14


# --- CWE-502: unsafe deserialization -----------------------------------------


class _EvilPayload:
    def __init__(self, marker_path: str):
        self.marker_path = marker_path

    def __reduce__(self):
        return (_touch_file, (self.marker_path,))


def _touch_file(path: str) -> None:
    from pathlib import Path

    Path(path).touch()


def test_profile_pickle_cookie_executes_arbitrary_code(client, tmp_path):
    marker = tmp_path / "pwned_pickle"
    payload = base64.b64encode(pickle.dumps(_EvilPayload(str(marker)))).decode()

    client.get("/profile", headers={"Cookie": f"session_data={payload}"})

    assert marker.exists()


def test_profile_safe_rejects_non_json_cookie(client, tmp_path):
    marker = tmp_path / "pwned_pickle_safe"
    payload = base64.b64encode(pickle.dumps(_EvilPayload(str(marker)))).decode()

    response = client.get("/profile-safe", headers={"Cookie": f"session_data={payload}"})

    assert response.status_code == 400
    assert not marker.exists()


# --- CWE-22: path traversal ---------------------------------------------------


def test_files_path_traversal_reads_outside_data_dir(client):
    response = client.get("/files", params={"filename": "../secret.txt"})

    assert response.status_code == 200
    assert "TOP-SECRET-VALUE" in response.json()["content"]


def test_files_safe_blocks_path_traversal(client):
    response = client.get("/files-safe", params={"filename": "../secret.txt"})

    assert response.status_code == 400


def test_files_safe_allows_in_directory_access(client):
    response = client.get("/files-safe", params={"filename": "notes.txt"})

    assert response.status_code == 200
    assert "public note" in response.json()["content"]


# --- CWE-89: SQL injection -----------------------------------------------------


def test_search_sql_injection_returns_all_users(client):
    response = client.get("/users/search", params={"name": "' OR '1'='1"})

    usernames = {u["username"] for u in response.json()["users"]}
    assert usernames == {"alice", "bob", "admin_root"}


def test_search_safe_blocks_sql_injection(client):
    response = client.get("/users/search-safe", params={"name": "' OR '1'='1"})

    assert response.json()["users"] == []


def test_search_safe_allows_exact_match(client):
    response = client.get("/users/search-safe", params={"name": "alice"})

    assert response.json()["users"] == [{"username": "alice", "email": "alice@example.com"}]
