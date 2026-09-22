"""Intentionally vulnerable FastAPI application used as a benchmark fixture.

Each vulnerability class from the project proposal (command execution,
dynamic evaluation, unsafe deserialization, path traversal, SQL injection)
has one VULNERABLE endpoint and one SAFE counterpart with the same shape.
This gives the reachability engine and sandbox validator positive and
negative cases to be scored against (see ground_truth.json).

Local, offline use only. Never deploy this application or expose it to
a network.
"""

from __future__ import annotations

import ast
import base64
import ipaddress
import os
import pickle
import sqlite3
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Cookie, FastAPI, HTTPException, Query
from pydantic import BaseModel

DATA_DIR = (Path(__file__).parent / "data").resolve()


class CalcRequest(BaseModel):
    expression: str


def _seed_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, is_admin INTEGER)"
    )
    conn.executemany(
        "INSERT INTO users (username, email, is_admin) VALUES (?, ?, ?)",
        [
            ("alice", "alice@example.com", 0),
            ("bob", "bob@example.com", 0),
            ("admin_root", "admin@example.com", 1),
        ],
    )
    conn.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    _seed_db(conn)
    app.state.db = conn
    yield
    conn.close()


app = FastAPI(
    title="sectestgen-vulnerable-fastapi",
    lifespan=lifespan,
)


@app.get("/")
def index() -> dict:
    return {
        "warning": "intentionally vulnerable fixture, local use only",
        "see": "ground_truth.json",
    }


# --- CWE-78: OS command injection -------------------------------------------


@app.get("/ping/{host:path}")
def ping(host: str) -> dict:
    """VULNERABLE: host (path param) flows unsanitized into a shell command."""
    output = os.popen(f"ping -c 1 {host}").read()
    return {"output": output}


@app.get("/ping-safe/{host:path}")
def ping_safe(host: str) -> dict:
    """SAFE: host is validated as an IP address before use, no shell."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise HTTPException(status_code=400, detail="host must be a valid IP address")

    result = subprocess.run(
        ["ping", "-c", "1", host], capture_output=True, text=True, timeout=5
    )
    return {"output": result.stdout}


# --- CWE-95: dynamic evaluation ---------------------------------------------


_SAFE_NODES = (
    ast.Expression,
    ast.BinOp,
    ast.UnaryOp,
    ast.Constant,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.Pow,
    ast.USub,
    ast.UAdd,
)


def _safe_arithmetic_eval(expression: str) -> float:
    tree = ast.parse(expression, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, _SAFE_NODES):
            raise ValueError(f"disallowed expression element: {type(node).__name__}")
    return eval(compile(tree, "<safe-expr>", "eval"))  # noqa: S307 (restricted AST above)


@app.post("/calc")
def calc(payload: CalcRequest) -> dict:
    """VULNERABLE: body field passed straight to eval()."""
    return {"result": eval(payload.expression)}  # noqa: S307


@app.post("/calc-safe")
def calc_safe(payload: CalcRequest) -> dict:
    """SAFE: only a restricted arithmetic AST is evaluated."""
    try:
        return {"result": _safe_arithmetic_eval(payload.expression)}
    except (ValueError, SyntaxError, TypeError, ZeroDivisionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --- CWE-502: unsafe deserialization -----------------------------------------


@app.get("/profile")
def profile(session_data: str | None = Cookie(default=None)) -> dict:
    """VULNERABLE: cookie value is base64+pickle deserialized."""
    if session_data is None:
        return {"user": None}
    data = pickle.loads(base64.b64decode(session_data))
    return {"user": data}


@app.get("/profile-safe")
def profile_safe(session_data: str | None = Cookie(default=None)) -> dict:
    """SAFE: cookie value is base64+JSON decoded instead of pickled."""
    import json

    if session_data is None:
        return {"user": None}
    try:
        data = json.loads(base64.b64decode(session_data))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"invalid session cookie: {exc}")
    return {"user": data}


# --- CWE-22: path traversal ---------------------------------------------------


@app.get("/files")
def read_file(filename: str = Query(...)) -> dict:
    """VULNERABLE: filename is joined into a path without containment checks."""
    target = DATA_DIR / filename
    return {"content": target.read_text()}


@app.get("/files-safe")
def read_file_safe(filename: str = Query(...)) -> dict:
    """SAFE: resolved path is required to stay inside DATA_DIR."""
    target = (DATA_DIR / filename).resolve()
    if not target.is_relative_to(DATA_DIR):
        raise HTTPException(status_code=400, detail="path traversal rejected")
    return {"content": target.read_text()}


# --- CWE-89: SQL injection -----------------------------------------------------


@app.get("/users/search")
def search_users(name: str = Query(...)) -> dict:
    """VULNERABLE: name is interpolated directly into the SQL string."""
    conn: sqlite3.Connection = app.state.db
    cursor = conn.execute(f"SELECT username, email FROM users WHERE username = '{name}'")
    rows = cursor.fetchall()
    return {"users": [{"username": r[0], "email": r[1]} for r in rows]}


@app.get("/users/search-safe")
def search_users_safe(name: str = Query(...)) -> dict:
    """SAFE: name is bound as a parameter, never concatenated into SQL."""
    conn: sqlite3.Connection = app.state.db
    cursor = conn.execute("SELECT username, email FROM users WHERE username = ?", (name,))
    rows = cursor.fetchall()
    return {"users": [{"username": r[0], "email": r[1]} for r in rows]}
